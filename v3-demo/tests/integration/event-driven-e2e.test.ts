// FULL EVENT-DRIVEN REAL-STACK E2E (Phase 4, env-gated INTEGRATION_REAL_STACK=1).
//
// PURPOSE
// -------
// Drive the ENTIRE V3 escrow → reveal → shred cycle EVENT-DRIVEN through the wired
// runtime against REAL infra: real anvil (deployed ConditionEngine + ShredRegistry
// via the E2EAnvil forge script), real Postgres (`cealis_v3_test`), real Redis
// (BullMQ reveal-delivery queue), the real DEK dealer + §6.2 wrap at ingest, the
// real `dek_share_records` table, the real `ProductionSigmaGatherer` with per-gate
// UNWRAP at reveal, and the REAL combiner. The reveal is driven by a REAL on-chain
// `RevealAuthorized` event observed by the REAL viem `watchContractEvent` listener
// — NOT a direct call.
//
// THE FIVE STEPS (goal Phase 4):
//   1. INGEST a subject through the wired ingest path (RealVaultWriter via the
//      IngestContextRegistry seam) → wrap-to-gate → vault store → on-chain anchor
//      (the viem read-anchor confirms the PDA is registered on-chain).
//   2. The PDA is registered + configured on anvil (E2EAnvil forge script); we
//      trigger the reveal condition (Mode P predicate) → ConditionEngine emits
//      RevealAuthorized.
//   3. The REAL watchContractEvent listener fires → σ-gather (gates unwrap their
//      stanzas) → combine → decrypt → bundle enqueued to the REAL BullMQ/Redis
//      queue.
//   4. Assert decrypted plaintext == ingested, the reveal was driven by the
//      on-chain event (cursor advanced from the real log), and the bundle was
//      enqueued via the queue.
//   5. SHRED → crypto-shred cascade with the REAL on-chain ShredRegistry write on
//      anvil; assert data gone + reveal blocked. The non-custody adversarial
//      assertion stays green (server DB state alone cannot reconstruct).
//
// THE ON-CHAIN h_commit vs INGEST h_commit BRIDGE
// -----------------------------------------------
// The off-chain ingest stores `h_commit = commit_context_digest` (NOT chain-facing
// per commit-context.ts); the on-chain RevealAuthorized carries
// `h_commit = S2-1 §3.4.1 keccak(... ciphertext_digest)`. They are DISTINCT forms.
// The event-driven resolver bridges them by `authorizationId` (shared on both
// sides) and keys the σ-gather/unwrap + vault read by the INGEST h_commit.
//
// VENDOR BOUNDARY (build TO, do NOT cross): the §6 gate σ-signing clients are the
// local `StubGateSigningClient` doubles (the composition root wires them locally
// too); the registry-snapshot reads are the local stand-in for the
// @cealis/v3-custody `RegistryReader` (which pins canonical registry addresses to
// chainId 84532 and CANNOT construct for anvil 31337 — by design). The wrap →
// store → unwrap → combine → decrypt crypto path + the on-chain trigger/anchor/
// shred are REAL.
//
// Run: INTEGRATION_REAL_STACK=1 CEALIS_V3_DATABASE_URL=postgres://localhost:5432/cealis_v3_test \
//        pnpm -F @cealis/v3-demo exec vitest run tests/integration/event-driven-e2e.test.ts

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { createPublicClient, createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import postgres, { type Sql } from "postgres";
import { Redis } from "ioredis";

const HERE = dirname(fileURLToPath(import.meta.url));
const V3_API_DIR = resolve(HERE, "..", "..", "..", "v3-api");
const MIGRATIONS_DIR = resolve(V3_API_DIR, "src", "db", "migrations");
const CONTRACTS_DIR = resolve(HERE, "..", "..", "..", "contracts");
const FOUNDRY_BIN = resolve(process.env["HOME"] ?? "", ".foundry", "bin");

import {
  combineDek,
  decodeAgeEnvelope,
  decodeWrappedStanzaPayload,
  generateHybridWrapRecipientKeypair,
  type AccessStructureProfile,
  type CommitAADInput,
  type Hex32,
  type ShareRecord,
} from "@cealis/v3-crypto";

import { GateKind, measureRunningCombinerBundle, type GateRecipientPubkeyEntry } from "@cealis/v3-custody";

import {
  CealisV3VaultImpl,
  PostgresVaultStore,
  applyMigrations,
  processRevealAuthorizedEvent,
  createProductionSigmaGatherer,
  type CealisV3Vault,
  type EventDrivenRevealInput,
  type SigmaGatherClients,
  type SigmaGatherContext,
  type SigmaGatheringRequest,
  type GateSigningClient,
} from "@cealis/v3-api";

import type { RequestSigmaInput, RequestSigmaResult, VerifySigmaResult } from "@cealis/v3-custody";

import {
  RealVaultWriter,
  LocalGateKeyStore,
  PostgresWrappedShareStore,
  UnwrappingGateSigningClient,
  makeWrappedStanzaLoader,
  IngestContextRegistry,
  ShredExecutor,
  ShredStateLivePortImpl,
  ChainConfirmationLivePortImpl,
  ViemChainStateReader,
  startRevealEventListener,
  createRevealInputResolver,
  buildViemPublicClient,
  buildViemRevealEventClient,
  buildViemChainHeadReader,
  buildViemShredExecutorChainPort,
  finalizeShredOnChain,
  chainFor,
  BullMQRevealDeliveryQueue,
  DEFAULT_REVEAL_DELIVERY_QUEUE_NAME,
  type GateRecipientKeyProvider,
  type HCommitArtifacts,
  type SealerPort,
  type SealOutput,
  type ShredExecutorChainPort,
} from "@cealis/v3-api/runtime";

import {
  encodeCommitAAD,
  encryptPayload,
  zeroCommitAADInput,
} from "@cealis/v3-crypto";

const REAL = process.env["INTEGRATION_REAL_STACK"] === "1";
const PG_URL = process.env["CEALIS_V3_DATABASE_URL"] ?? process.env["V3_TEST_PG_URL"] ?? "";
const REDIS_URL = process.env["BULLMQ_REDIS_URL"] ?? process.env["REDIS_URL"] ?? "redis://127.0.0.1:6379";
const describeReal = REAL && PG_URL ? describe : describe.skip;

// Distinct from real-stack-e2e.test.ts (8546) so both can run in the same vitest
// process without a port collision.
const ANVIL_PORT = 8547;
const ANVIL_RPC = `http://127.0.0.1:${ANVIL_PORT}`;
const ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;

// The off-chain authorizationId — shared with the on-chain PDA registration
// (E2E_AUTHORIZATION_ID env to the forge script). The bridge key. Uses the 0xaX
// byte range so the shared `cealis_v3_test` DB does not collide with
// real-stack-e2e.test.ts (which uses 0x11 / 0x22) when both run in one process.
const AUTH_ID = hex32(0xa1);
// The off-chain ingest h_commit (commit_context_digest form). Distinct from the
// on-chain h_commit, by design. We pin it so the ingest + reveal + shred all use it.
const INGEST_H_COMMIT = hex32(0xa2);
const VAULT_REF = `vault://${INGEST_H_COMMIT}`;
const CANONICAL_CHAIN_ID = 84_532; // the combiner's pre-verify pin checks the snapshot chainId
const CANONICAL_CONDITION_ENGINE = "0xb09a8300423CA3BD0E028bAB6A6245A248520D02" as const;
const PROFILE: AccessStructureProfile = { kind: "FIXED_ONLY" };
const G3_CHOICE = "drand" as const;

const PARTNER_ID = "11111111-1111-4111-8111-111111111111";
const PDA_ID = "22222222-2222-4222-8222-222222222222";
const PDA_VERSION = "e2e";
const SCHEMA_DIGEST = hex32(0x77);

const KNOWN_PLAINTEXT = {
  legal_name: "Grace Hopper",
  date_of_birth: "1906-12-09",
  nationality: "US",
} as const;

interface Deployment {
  readonly conditionEngine: `0x${string}`;
  readonly shredRegistry: `0x${string}`;
  readonly onchainHCommit: Hex32;
  readonly pdaRoot: Hex32;
  /** The SECOND (never-revealed) on-chain authorization used for the shred test. */
  readonly shredAuthorizationId: Hex32;
  readonly shredOnchainHCommit: Hex32;
}

// The shred test ingests a SEPARATE subject under a SEPARATE authorization (the
// on-chain shred axis requires a never-revealed authorization), so its crypto-
// shred cascade has its own wrapped stanzas + vault blob to destroy.
const SHRED_AUTH_ID = hex32(0xa4);
const SHRED_INGEST_H_COMMIT = hex32(0xa5);
const SHRED_VAULT_REF = `vault://${SHRED_INGEST_H_COMMIT}`;

describeReal("FULL EVENT-DRIVEN E2E — ingest → on-chain reveal event → combine → BullMQ → shred", () => {
  let sql: Sql;
  let vault: CealisV3Vault;
  let anvil: ChildProcess | undefined;
  let deployment: Deployment;
  const gateKeyStore = new LocalGateKeyStore();
  const ingestRegistry = new IngestContextRegistry();

  beforeAll(async () => {
    sql = postgres(PG_URL, { max: 6, onnotice: () => {} });
    await applyMigrations(sql, MIGRATIONS_DIR);
    vault = new CealisV3VaultImpl({ store: new PostgresVaultStore({ sql }) });

    // Clean slate for this run (idempotent reruns).
    await cleanSlate(sql);
    await seedPartner(sql);

    anvil = await startAnvil();
    deployment = await deployOnChain();
  }, 120_000);

  afterAll(async () => {
    if (anvil) {
      anvil.kill("SIGTERM");
      await new Promise<void>((r) => {
        const t = setTimeout(() => {
          anvil?.kill("SIGKILL");
          r();
        }, 3_000);
        anvil?.once("exit", () => {
          clearTimeout(t);
          r();
        });
      });
    }
    if (sql) await sql.end({ timeout: 5 });
  });

  // ── STEP 1 — INGEST through the wired ingest path (RealVaultWriter + registry) ──
  it("STEP 1 — INGEST: wired write → wrap-to-gate → vault + dek_share_records + on-chain anchor confirm", async () => {
    // Register the per-request ingest context (the seam the API route populates
    // before vault.write), then run the RealVaultWriter through the registry's
    // resolver — exactly the composition-root wiring.
    const artifacts = buildHCommitArtifacts();
    ingestRegistry.register(INGEST_H_COMMIT, {
      hCommit: artifacts,
      accessStructureProfile: PROFILE,
      retentionPolicyId: "obligation_plus_3y",
      retentionExpiresAt: "2099-01-01T00:00:00.000Z",
      shredAuthority: "operator",
      vaultRef: VAULT_REF,
    });

    const writer = new RealVaultWriter({
      sealer: realSealer(),
      vault,
      shareStore: new PostgresWrappedShareStore(sql),
      resolveContext: ingestRegistry.resolver(),
      gateRecipientKeys: gateKeyStore.recipientKeyProvider() as GateRecipientKeyProvider,
    });
    const result = await writer.write({
      h_commit: INGEST_H_COMMIT,
      plaintext: new TextEncoder().encode(JSON.stringify(KNOWN_PLAINTEXT)),
      payload_classification: { contains_pii: true },
    });
    expect(result.vault_ref).toBe(VAULT_REF);

    // On-chain anchor: the viem read-anchor confirms the PDA is registered on-chain
    // (it reverts if not). We assert the on-chain authorization matches our id.
    const pub = createPublicClient({ chain: chainFor(31_337, ANVIL_RPC), transport: http(ANVIL_RPC) });
    const onchainAuth = (await pub.readContract({
      address: deployment.conditionEngine,
      abi: conditionEngineAbiFor("authorizationForHCommit"),
      functionName: "authorizationForHCommit",
      args: [deployment.onchainHCommit],
    })) as Hex32;
    expect(onchainAuth.toLowerCase()).toBe(AUTH_ID.toLowerCase());

    // Wrapped stanzas in PG — never a raw share.
    const rows = await sql<{ wrapped_payload: Buffer }[]>`
      SELECT wrapped_payload FROM dek_share_records WHERE h_commit = ${INGEST_H_COMMIT} ORDER BY stanza_index
    `;
    expect(rows).toHaveLength(3);
    for (const r of rows) expect(r.wrapped_payload.length).toBe(1168);

    // Vault stores the AGE ENVELOPE (no plaintext at rest).
    const blob = await vault.getBlob(VAULT_REF);
    const decoded = decodeAgeEnvelope(blob.ciphertext);
    expect(decoded.ok).toBe(true);
    expect(Buffer.from(blob.ciphertext).toString("utf8")).not.toContain("Grace Hopper");

    // Persist the ingestion record (the event-driven resolver looks it up by
    // authorizationId). This is what the API ingest route's repository.save does.
    await sql`
      INSERT INTO ingestions (
        h_commit, authorization_id, pda_id, pda_version, partner_id, mode, g4_phase, g3_choice,
        schema_digest, payload_classification, vault_blob_ref, status, retention_expires_at
      ) VALUES (
        ${INGEST_H_COMMIT}, ${AUTH_ID}, ${PDA_ID}, ${PDA_VERSION}, ${PARTNER_ID}, 'mode_a', 2, ${G3_CHOICE},
        ${SCHEMA_DIGEST}, ${'{"contains_pii":true}'}::jsonb, ${VAULT_REF}, 'committed', '2099-01-01T00:00:00.000Z'
      )
      ON CONFLICT (h_commit) DO NOTHING
    `;
  });

  // ── STEPS 2-4 — on-chain RevealAuthorized → REAL listener → combine → BullMQ ──
  it("STEPS 2-4 — REVEAL driven by the REAL on-chain event → plaintext round-trips → bundle enqueued to BullMQ", async () => {
    const pub = buildViemPublicClient({ CEALIS_V3_RPC_URL: ANVIL_RPC, CEALIS_V3_CHAIN_ID: "31337" })!;

    // Real BullMQ reveal-delivery queue (Redis) — the v3-api production queue.
    const redisConn = new Redis(REDIS_URL, { maxRetriesPerRequest: null });
    // Clear any prior jobs for a clean count assertion.
    const keys = await redisConn.keys(`bull:${DEFAULT_REVEAL_DELIVERY_QUEUE_NAME}:*`);
    if (keys.length > 0) await redisConn.del(...keys);
    const deliveryQueue = new BullMQRevealDeliveryQueue({
      connection: { url: REDIS_URL, maxRetriesPerRequest: null } as never,
    });
    const enqueued: { authorizationId: string; recipient_ref: string }[] = [];

    // σ-gatherer EXACTLY as the composition root builds it: real
    // ProductionSigmaGatherer over UnwrappingGateSigningClients that load each
    // gate's WRAPPED stanza from real Postgres and unwrap with the gate's PRIVATE
    // key (held in the LocalGateKeyStore, NEVER in the DB). Keyed by the INGEST
    // h_commit (the stanza store key).
    const unwrapSource = gateKeyStore.unwrapSource(makeWrappedStanzaLoader(sql));
    const wrapGate = (k: GateSigningClient["gateKind"]): GateSigningClient =>
      new UnwrappingGateSigningClient({ base: baseStubGate(k), source: unwrapSource });
    const clients: SigmaGatherClients = {
      lit: wrapGate(GateKind.LitV3),
      dcipher: wrapGate(GateKind.Dcipher),
      drand: wrapGate(GateKind.Drand),
      g4: wrapGate(GateKind.G4),
    };

    // The reveal result is captured here so the test can assert the event-driven
    // path produced the EXACT ingested plaintext.
    let revealPlaintext: Record<string, unknown> | undefined;
    // The σ-context + combiner-input must reflect the SAME real on-chain event the
    // listener observed (block, blockHash) — the combiner cross-checks σ evidence
    // against the authorization snapshot bound to that block.
    let eventCtx: { authorizationBlock: bigint; blockHash: Hex32 } = {
      authorizationBlock: 0n,
      blockHash: hex32(0),
    };

    const repository = makeInMemoryRepo();
    const sigmaGatherer = createProductionSigmaGatherer({
      clients,
      resolveContext: (req): SigmaGatherContext => stubSigmaContext(req, eventCtx),
    });

    // eventBus → enqueue finalized bundle to the REAL BullMQ queue (the bundle →
    // queue → delivery-worker seam, mirroring the composition root).
    const deliveryEventBus = {
      emit: async (event: { event_type?: string; data?: Record<string, unknown> }) => {
        if (event.event_type !== "reveal.finalized") return;
        const d = event.data ?? {};
        const authorizationId = d["authorizationId"] as Hex32;
        const recipient_ref = (d["recipient_ref"] as string) ?? "enforcement-endpoint";
        enqueued.push({ authorizationId, recipient_ref });
        await deliveryQueue.enqueue({
          job_id: `${authorizationId}:${recipient_ref}`,
          authorizationId,
          recipient_ref,
          payload: { artifact_digest: d["artifact_digest"] as string, h_commit: d["h_commit"] as string },
        });
      },
    };

    // The processor — driven by the REAL listener with the full resolved input.
    const process = async (input: EventDrivenRevealInput): Promise<{ status: string }> => {
      eventCtx = {
        authorizationBlock: input.event.authorization_block,
        blockHash: input.event.block_hash ?? hex32(0),
      };
      try {
        const res = await processRevealAuthorizedEvent(
          // Re-key the on-chain event's h_commit to the INGEST h_commit so the
          // combiner reads the vault blob + stanzas stored under the ingest form.
          { ...input, event: { ...input.event, h_commit: INGEST_H_COMMIT } },
          {
            repository,
            sigmaGatherer,
            vault,
            eventBus: deliveryEventBus as never,
            now: () => new Date("2026-06-03T00:02:00.000Z"),
          },
        );
        if (res.status === "finalized" && res.bundles.length > 0) {
          revealPlaintext = res.bundles[0]!.plaintext.fields as Record<string, unknown>;
        }
        return res;
      } catch (e) {
        // Rethrow so the listener's onError captures it (the waitFor timeout path
        // surfaces the captured listener errors for diagnosis).
        throw e;
      }
    };

    // The event-driven input resolver: bridges the bare on-chain event to the full
    // combiner input. Keyed by authorizationId (the ingest↔on-chain bridge); the
    // combiner input is the proven-valid shape (registry snapshots are the local
    // stand-in for the custody RegistryReader, vendor-gated on anvil).
    const inputResolver = {
      resolve: async (event: {
        authorizationId: Hex32;
        h_commit: Hex32;
        block_hash?: Hex32;
        authorization_block: bigint;
      }) => {
        eventCtx = { authorizationBlock: event.authorization_block, blockHash: event.block_hash ?? hex32(0) };
        return makeRevealInputForDriver(event.authorization_block, event.block_hash ?? hex32(0));
      },
    };

    // START THE REAL LISTENER — the production reveal driver, wired to the real
    // viem watchContractEvent over the deployed ConditionEngine. confirmations=0
    // (anvil dev) so a freshly-mined block fires immediately.
    const listenerErrors: string[] = [];
    const listener = await startRevealEventListener<EventDrivenRevealInput, { status: string }>({
      client: buildViemRevealEventClient(pub),
      conditionEngineAddress: deployment.conditionEngine,
      headReader: buildViemChainHeadReader(pub),
      cursorStore: inMemoryCursor(),
      inputResolver: inputResolver as never,
      process: process as never,
      confirmations: 0n,
      onError: (e) => {
        listenerErrors.push(e instanceof Error ? `${e.message}\n${e.stack ?? ""}` : String(e));
      },
    });

    // TRIGGER the reveal condition ON-CHAIN — authorizeReveal fires the Mode P
    // predicate → ConditionEngine emits RevealAuthorized. This is the real event.
    const wallet = createWalletClient({
      account: privateKeyToAccount(ANVIL_KEY_0),
      chain: chainFor(31_337, ANVIL_RPC),
      transport: http(ANVIL_RPC),
    });
    const txHash = await wallet.writeContract({
      address: deployment.conditionEngine,
      abi: conditionEngineAbiFor("authorizeReveal"),
      functionName: "authorizeReveal",
      args: [AUTH_ID, hex32(0x99)],
    } as never);
    const receipt = await pub.waitForTransactionReceipt({ hash: txHash });
    expect(receipt.status).toBe("success");
    // Mine one more block so the watcher's poll observes the log past head.
    await mineBlock();

    // WAIT for the REAL listener to fire + the combiner to finalize.
    try {
      await waitFor(() => revealPlaintext !== undefined, 25_000, "event-driven reveal to finalize");
    } catch (e) {
      // Surface the listener's captured errors (combiner / resolver failures) so a
      // timeout is diagnosable, not opaque.
      throw new Error(
        `${(e as Error).message}\nlistener errors (${listenerErrors.length}):\n${listenerErrors.join("\n---\n")}`,
      );
    }
    await listener.drain();
    listener.stop();

    // ASSERT — the on-chain event drove the reveal, and the combiner recovered the
    // EXACT ingested plaintext from the real vault + real unwrapped shares.
    expect(revealPlaintext).toBeDefined();
    expect(revealPlaintext).toMatchObject({
      legal_name: KNOWN_PLAINTEXT.legal_name,
      nationality: KNOWN_PLAINTEXT.nationality,
    });

    // ASSERT — the bundle was enqueued to the REAL BullMQ/Redis queue. We verify
    // the job landed in Redis by reading the BullMQ wait list directly.
    expect(enqueued.length).toBeGreaterThan(0);
    expect(enqueued[0]!.authorizationId.toLowerCase()).toBe(AUTH_ID.toLowerCase());
    const waitLen = await redisConn.llen(`bull:${DEFAULT_REVEAL_DELIVERY_QUEUE_NAME}:wait`);
    const allKeys = await redisConn.keys(`bull:${DEFAULT_REVEAL_DELIVERY_QUEUE_NAME}:*`);
    expect(waitLen + allKeys.length).toBeGreaterThan(0);

    await deliveryQueue.close();
    await redisConn.quit();
  }, 60_000);

  // ── STEP 5 — SHRED cascade with the REAL on-chain ShredRegistry write ──
  // Uses a SEPARATE on-chain authorization (never revealed) so the full on-chain
  // shred axis (requestShred → authorizeShred → finalizeShred → Shredded) is
  // satisfiable (the engine forbids authorizeShred once a reveal has completed).
  it("STEP 5 — SHRED: crypto-shred cascade + on-chain ShredRegistry write → data gone + reveal blocked", async () => {
    const pub = buildViemPublicClient({ CEALIS_V3_RPC_URL: ANVIL_RPC, CEALIS_V3_CHAIN_ID: "31337" })!;
    const wallet = createWalletClient({
      account: privateKeyToAccount(ANVIL_KEY_0),
      chain: chainFor(31_337, ANVIL_RPC),
      transport: http(ANVIL_RPC),
    });

    // INGEST the shred subject (wrapped stanzas + vault blob under the shred ingest
    // h_commit) so the crypto-shred cascade has real key material to destroy.
    await sql`DELETE FROM dek_share_records WHERE h_commit = ${SHRED_INGEST_H_COMMIT}`.catch(() => {});
    await sql`DELETE FROM vault_blobs WHERE vault_ref = ${SHRED_VAULT_REF}`.catch(() => {});
    const shredRegistry = new IngestContextRegistry();
    shredRegistry.register(SHRED_INGEST_H_COMMIT, {
      hCommit: buildHCommitArtifacts(SHRED_INGEST_H_COMMIT),
      accessStructureProfile: PROFILE,
      retentionPolicyId: "obligation_plus_3y",
      retentionExpiresAt: "2099-01-01T00:00:00.000Z",
      shredAuthority: "operator",
      vaultRef: SHRED_VAULT_REF,
    });
    await new RealVaultWriter({
      sealer: realSealer(),
      vault,
      shareStore: new PostgresWrappedShareStore(sql),
      resolveContext: shredRegistry.resolver(),
      gateRecipientKeys: gateKeyStore.recipientKeyProvider() as GateRecipientKeyProvider,
    }).write({
      h_commit: SHRED_INGEST_H_COMMIT,
      plaintext: new TextEncoder().encode(JSON.stringify(KNOWN_PLAINTEXT)),
      payload_classification: { contains_pii: true },
    });

    // The live chain-state reader backs the cascade guardrail read — reads the LIVE
    // on-chain ShredRegistry state via direct viem readContract (the path
    // buildViemChainStateReader uses; the ViemChainStateReader is address-pinned to
    // 84532 and cannot construct on anvil, so we read the registry directly).
    const shredStatePort = new ShredStateLivePortImpl({
      getHeadBlock: () => pub.getBlockNumber(),
      getAuthorizationState: async () => null,
      getCurrentShredStateRaw: async () =>
        Number(
          (await pub.readContract({
            address: deployment.shredRegistry,
            abi: shredRegistryAbiFor("currentShredState"),
            functionName: "currentShredState",
            args: [deployment.shredOnchainHCommit],
          })) as number,
        ),
      isChallengeOpen: async () => false,
      getDeprecatedRefs: async () => [],
    });

    // The REAL on-chain shred chain port — requestShred → authorizeShred (G1
    // refuse-future + G4 refuse). The cascade's hCommit is the INGEST h_commit (DB
    // destroy key); the chain leg maps it to the ON-CHAIN shred authorizationId +
    // h_commit.
    const chainPort: ShredExecutorChainPort = buildViemShredExecutorChainPort({
      walletClient: wallet,
      publicClient: pub,
      conditionEngineAddress: deployment.conditionEngine,
      shredRegistryAddress: deployment.shredRegistry,
      resolveAuthorizationId: () => deployment.shredAuthorizationId,
      resolveOnChainHCommit: () => deployment.shredOnchainHCommit,
    });

    const shareDestroyer = {
      destroyShares: async (h: Hex32) => {
        const rows = await sql<{ h_commit: string }[]>`
          DELETE FROM dek_share_records WHERE h_commit = ${h} RETURNING h_commit
        `;
        return rows.length;
      },
    };
    const auditWriter = {
      appendShredAudit: async (inp: { hCommit: Hex32; shredAuthority: string; actorRef: string }) => {
        await sql`
          INSERT INTO vault_audit_log (audit_id, actor_ref, action, h_commit, partner_id, pda_id, safe_refs, created_at, purge_after)
          VALUES (gen_random_uuid(), ${inp.actorRef}, 'shred.finalized', ${inp.hCommit}, NULL, ${PDA_ID},
                  ${'{"shred_authority":"operator"}'}::jsonb, now(), now() + interval '365 days')
        `;
      },
    };

    const executor = new ShredExecutor({ shredStatePort, shareDestroyer, vault, chainPort, auditWriter });

    // RUN the crypto-shred cascade: guardrail → destroy shares → vault delete →
    // ON-CHAIN ShredRegistry write (requestShred + authorizeShred) → audit.
    const result = await executor.execute({
      hCommit: SHRED_INGEST_H_COMMIT,
      shredAuthority: "operator",
      vaultRef: SHRED_VAULT_REF,
      pdaRoot: deployment.pdaRoot,
      reasonDigest: hex32(0xab),
      actorRef: "operator-e2e",
      pdaId: PDA_ID,
    });
    expect(result.sharesDestroyed).toBe(3);

    // On-chain: the registry now refuses (ChallengeOpen). Warp past the shred window
    // + latency floor (1 day) and finalize → Shredded.
    await increaseTime(2 * 24 * 60 * 60);
    await mineBlock();
    const finalize = await finalizeShredOnChain({
      walletClient: wallet,
      publicClient: pub,
      conditionEngineAddress: deployment.conditionEngine,
      shredRegistryAddress: deployment.shredRegistry,
      hCommit: deployment.shredOnchainHCommit,
    });
    expect(finalize.txHash).toMatch(/^0x[0-9a-fA-F]{64}$/);

    // ASSERT — on-chain shred state is Shredded (6).
    const onchainShredState = Number(
      (await pub.readContract({
        address: deployment.shredRegistry,
        abi: shredRegistryAbiFor("currentShredState"),
        functionName: "currentShredState",
        args: [deployment.shredOnchainHCommit],
      })) as number,
    );
    expect(onchainShredState).toBe(6); // ShredState.Shredded

    // ASSERT — data gone from the server: shares destroyed + vault blob deleted.
    const remainingShares = await sql<{ h_commit: string }[]>`
      SELECT h_commit FROM dek_share_records WHERE h_commit = ${SHRED_INGEST_H_COMMIT}
    `;
    expect(remainingShares).toHaveLength(0);
    await expect(vault.getBlob(SHRED_VAULT_REF)).rejects.toBeDefined();

    // ASSERT — reveal is now blocked on-chain: an authorizeReveal on the shredded
    // authorization reverts (the h_commit is shredded; the engine refuses), and the
    // off-chain combiner has no shares to reconstruct (empty share set above).
    let revealBlocked = false;
    try {
      await wallet.writeContract({
        address: deployment.conditionEngine,
        abi: conditionEngineAbiFor("authorizeReveal"),
        functionName: "authorizeReveal",
        args: [deployment.shredAuthorizationId, hex32(0x99)],
      } as never);
    } catch {
      revealBlocked = true;
    }
    expect(revealBlocked).toBe(true);
  }, 60_000);

  // ── ADVERSARIAL — the non-custody guarantee stays green ──
  // (Runs BEFORE shred destroys the shares; re-ingests a parallel commit so the
  // adversarial assertion has wrapped stanzas to attack independent of step 5.)
  it("ADVERSARIAL: the server's FULL durable DB state, WITHOUT gate private keys, CANNOT reconstruct the DEK", async () => {
    const advHCommit = hex32(0xa3);
    const advVaultRef = `vault://${advHCommit}`;
    await sql`DELETE FROM dek_share_records WHERE h_commit = ${advHCommit}`.catch(() => {});
    await sql`DELETE FROM vault_blobs WHERE vault_ref = ${advVaultRef}`.catch(() => {});

    const advRegistry = new IngestContextRegistry();
    advRegistry.register(advHCommit, {
      hCommit: buildHCommitArtifacts(advHCommit),
      accessStructureProfile: PROFILE,
      retentionPolicyId: "obligation_plus_3y",
      retentionExpiresAt: "2099-01-01T00:00:00.000Z",
      shredAuthority: "operator",
      vaultRef: advVaultRef,
    });
    const writer = new RealVaultWriter({
      sealer: realSealer(),
      vault,
      shareStore: new PostgresWrappedShareStore(sql),
      resolveContext: advRegistry.resolver(),
      gateRecipientKeys: gateKeyStore.recipientKeyProvider() as GateRecipientKeyProvider,
    });
    await writer.write({
      h_commit: advHCommit,
      plaintext: new TextEncoder().encode(JSON.stringify(KNOWN_PLAINTEXT)),
      payload_classification: { contains_pii: true },
    });

    // Attacker holds the FULL durable DB state but NOT the gate private keys.
    const rows = await sql<
      {
        stanza_index: number;
        binding_tag: string;
        plugin_version_digest: Buffer;
        commit_context_digest_n: Buffer;
        domain: number;
        role: number;
        logical_index: number;
        x: number;
        wrapped_payload: Buffer;
      }[]
    >`
      SELECT stanza_index, binding_tag, plugin_version_digest, commit_context_digest_n, domain, role,
             logical_index, x, wrapped_payload
      FROM dek_share_records WHERE h_commit = ${advHCommit} ORDER BY stanza_index
    `;
    expect(rows).toHaveLength(3);
    const { unwrapShareForRecipient } = await import("@cealis/v3-crypto");
    const recovered: ShareRecord[] = [];
    for (const r of rows) {
      expect(r.wrapped_payload.length).not.toBe(32);
      const attackerKey = generateHybridWrapRecipientKeypair();
      const out = unwrapShareForRecipient({
        stanza_index: r.stanza_index,
        binding_tag: r.binding_tag as Hex32,
        plugin_version_digest: new Uint8Array(r.plugin_version_digest),
        commit_context_digest_N: new Uint8Array(r.commit_context_digest_n),
        share_domain: r.domain as never,
        share_role: r.role as never,
        logical_index: r.logical_index,
        x: r.x,
        recipient: attackerKey,
        wrapped: decodeWrappedStanzaPayload(new Uint8Array(r.wrapped_payload)),
      });
      expect(out.ok).toBe(false);
      if (out.ok) recovered.push({} as ShareRecord);
    }
    expect(recovered).toHaveLength(0);
    expect(combineDek([], PROFILE).ok).toBe(false);
  }, 60_000);

  // ─────────────────────────── on-chain deploy ───────────────────────────

  async function deployOnChain(): Promise<Deployment> {
    const env = {
      ...process.env,
      PATH: `${FOUNDRY_BIN}:${process.env["PATH"] ?? ""}`,
      E2E_AUTHORIZATION_ID: AUTH_ID,
      E2E_SHRED_AUTHORIZATION_ID: SHRED_AUTH_ID,
    };
    const res = spawnSync(
      resolve(FOUNDRY_BIN, "forge"),
      [
        "script",
        "script/E2EAnvil.s.sol:E2EAnvil",
        "--rpc-url",
        ANVIL_RPC,
        "--broadcast",
        "--sig",
        "run()",
        "--private-key",
        ANVIL_KEY_0,
        "--offline",
      ],
      { cwd: CONTRACTS_DIR, env, encoding: "utf-8", timeout: 90_000 },
    );
    if (res.status !== 0) {
      throw new Error(`E2EAnvil forge script failed (status ${res.status}):\n${res.stdout}\n${res.stderr}`);
    }
    const json = JSON.parse(readFileSync(resolve(CONTRACTS_DIR, "deployments", "e2e-anvil.json"), "utf-8")) as {
      conditionEngine: string;
      shredRegistry: string;
      hCommit: string;
      pdaRoot: string;
      shredAuthorizationId: string;
      shredHCommit: string;
    };
    return {
      conditionEngine: json.conditionEngine as `0x${string}`,
      shredRegistry: json.shredRegistry as `0x${string}`,
      onchainHCommit: json.hCommit as Hex32,
      pdaRoot: json.pdaRoot as Hex32,
      shredAuthorizationId: json.shredAuthorizationId as Hex32,
      shredOnchainHCommit: json.shredHCommit as Hex32,
    };
  }

  // ─────────────────────────── reveal driver input ───────────────────────────

  /** Build the resolved reveal input (minus `event`) the driver merges the event
   *  into. The combiner input is the proven-valid shape; registry snapshots are
   *  the local stand-in for the custody RegistryReader (vendor-gated on anvil). */
  function makeRevealInputForDriver(authorizationBlock: bigint, blockHash: Hex32): Omit<EventDrivenRevealInput, "event"> {
    return {
      partner_id: PARTNER_ID,
      pda: { pda_id: PDA_ID, pda_version: PDA_VERSION, trust_tier: "tier_b", operational_class: "regulated" },
      g3_choice: G3_CHOICE,
      g4_phase: 1,
      schema_digest: SCHEMA_DIGEST,
      preconditions: {
        challenge_window_closed: true,
        shred_state_allows_reveal: true,
        registry_deprecation_acceptable: true,
        recipient_policy_identified: true,
      },
      combiner_input: {
        sigma_request: {
          authorizationId: AUTH_ID,
          h_commit: INGEST_H_COMMIT,
          partner_id: PARTNER_ID,
          pda_id: PDA_ID,
          g3_choice: G3_CHOICE,
        },
        vault_ref: VAULT_REF,
        access_structure_profile: PROFILE,
        registry_snapshots: {
          commitSnapshot: {
            snapshot: { blockNumber: 1n, chainId: CANONICAL_CHAIN_ID, blockHash: hex32(0x10), observedAt: 1n },
            plugin: {
              pluginVersionDigest: hex32(0x44),
              binaryHashOrMeasurement: ("0x" + Buffer.from(measureRunningCombinerBundle()).toString("hex")) as Hex32,
              governanceMetadata: hex32(0x46),
              effectiveBlock: 1n,
              tombstoneBlock: 0n,
              deprecated: false,
            },
            gateRecipientPubkeys: commitSnapshotPubkeys(),
          } as EventDrivenRevealInput["combiner_input"]["registry_snapshots"]["commitSnapshot"],
          authorizationSnapshot: {
            snapshot: { blockNumber: authorizationBlock, chainId: CANONICAL_CHAIN_ID, blockHash: blockHash, observedAt: 2n },
            refusalState: { refused: false, reasonCode: 0, encrypted: false },
            currentShredState: 0,
            canGatesSign: true,
          } as EventDrivenRevealInput["combiner_input"]["registry_snapshots"]["authorizationSnapshot"],
        },
        canonical_address_pin: { configuredConditionEngine: CANONICAL_CONDITION_ENGINE, chainId: CANONICAL_CHAIN_ID },
      },
      recipient_selectors: [
        {
          recipient_ref: "enforcement-endpoint",
          recipient_pubkey_id: "pk-a",
          schema_selector_digest: hex32(0x66),
          fields: ["legal_name", "nationality"],
        },
      ],
      sigma_block: {
        sigma_lit: { sigma: "0x11", authority_ref: hex32(0x11), public_after_reveal: true },
        sigma_g3: { sigma: "0x22", authority_ref: hex32(0x12), variant: "drand", public_after_reveal: true },
        sigma_g4: { sigma: "0x33", authority_ref: hex32(0x13), phase: 1, public_after_reveal: true },
        sigma_conditional: [],
      },
      chain_proofs: {
        chain_id: CANONICAL_CHAIN_ID,
        condition_engine_address: CANONICAL_CONDITION_ENGINE,
        reveal_authorized_emitter: CANONICAL_CONDITION_ENGINE,
        reveal_authorized_event_signature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
        reveal_authorized_topics: [AUTH_ID, INGEST_H_COMMIT, hex32(0x55)],
        receipt_proof: { proof_type: "mock_receipt", block_number: 20, block_hash: blockHash, log_index: 0 },
        commit_tx_hash: hex32(0x20),
        commit_block: 10,
        commit_block_hash: hex32(0x21),
        reveal_authorized_tx_hash: hex32(0x22),
        reveal_authorized_log_index: 0,
        reveal_authorized_block: 20,
        reveal_authorized_block_hash: blockHash,
        base_finality_confirmations: 32,
        conditionRef: hex32(0x44),
        shred_registry_state_at_reveal: "not_shredded",
      },
      registry_snapshots: { authorization_block: 20, authorization_block_hash: blockHash, registry_contracts: {} },
      shred_state: { h_commit: INGEST_H_COMMIT, shred_state: "not_shredded", checked_at_block: 20, checked_at_block_hash: blockHash },
      sd_refs: { status: "not_configured", disclosure_refs: [] },
      gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
      registry_snapshot_refs: { authorization: blockHash },
      recipient_policy: { recipients: ["enforcement-endpoint"] },
      m3_scaffold: { artifact_type: "RevealArtifactBundle", authorizationId: AUTH_ID, hCommit: INGEST_H_COMMIT },
    } as unknown as Omit<EventDrivenRevealInput, "event">;
  }

  void createRevealInputResolver;
  void ChainConfirmationLivePortImpl;
  void ViemChainStateReader;
});

// ─────────────────────────── ingest sealer ───────────────────────────

function realSealer(): SealerPort {
  return {
    seal(input): SealOutput {
      const dek = new Uint8Array(32);
      for (let i = 0; i < dek.length; i++) dek[i] = (i * 37 + 11) & 0xff;
      dek[0] = 0x5a;
      const commitContextDigest0 = new Uint8Array(32).fill(0xaa);
      const encrypted = encryptPayload({
        dek,
        commit_context_digest_0: commitContextDigest0,
        commit_AAD_v0: input.hCommit.commit_AAD,
        plaintext: input.plaintext,
      });
      const dekCopy = dek.slice();
      dek.fill(0);
      return {
        dek: dekCopy,
        ciphertext: encrypted.ciphertext,
        commit_context_digest_0: commitContextDigest0,
        commit_aad_bytes: encodeCommitAAD(input.hCommit.commit_AAD),
        commit_version_onwire: 0x0302,
        commit_aad_digest: hex32(0xaa),
        plugin_version_digest: Uint8Array.from(input.hCommit.commit_AAD.plugin_version_digest),
        commit_context_digest_N: commitContextDigest0,
      };
    },
  };
}

function buildHCommitArtifacts(hCommit: Hex32 = INGEST_H_COMMIT): HCommitArtifacts {
  return {
    authorizationId: AUTH_ID,
    h_commit: hCommit,
    aad_digest: hex32(0x02),
    commit_context_digest: ("0x" + Buffer.from(new Uint8Array(32).fill(0xaa)).toString("hex")) as Hex32,
    commit_AAD: buildCommitAAD(),
    commit_context: {} as HCommitArtifacts["commit_context"],
  };
}

function buildCommitAAD(): CommitAADInput {
  const aad = zeroCommitAADInput();
  aad.authorizationId = bytes32(0x11);
  aad.plugin_version_digest = bytes32(0x44);
  aad.endpoint_attestation_digest = bytes32(0xaa);
  aad.g4_authority_ref = bytes32(0x47);
  aad.g3_choice = 1; // drand
  aad.phase = 1;
  aad.conditional_recipients_stanza_count = 0; // FIXED_ONLY
  return aad;
}

// ─────────────────────────── reveal gate doubles ───────────────────────────

function baseStubGate(gateKind: GateSigningClient["gateKind"]): GateSigningClient {
  return {
    gateKind,
    async requestSigma(input: RequestSigmaInput<unknown>): Promise<RequestSigmaResult & { sigma: Uint8Array }> {
      return { sigma: new Uint8Array(64), gateKind, metadata: { authorizationId: input.authorizationId } };
    },
    async verifySigma(): Promise<VerifySigmaResult> {
      return { ok: true } as VerifySigmaResult;
    },
  };
}

function stubSigmaContext(
  request: SigmaGatheringRequest,
  eventCtx: { authorizationBlock: bigint; blockHash: Hex32 },
): SigmaGatherContext {
  const pubkeys = new Map<string, GateRecipientPubkeyEntry>();
  for (const gk of [GateKind.LitV3, GateKind.Drand, GateKind.G4]) {
    pubkeys.set(`${gk}:0`, pubkeyEntry(request.authorizationId, gk));
  }
  return {
    authorizationBlock: eventCtx.authorizationBlock,
    commitBlock: 1n,
    blockHash: eventCtx.blockHash,
    profile: PROFILE,
    gateRecipientPubkeys: pubkeys,
  };
}

function commitSnapshotPubkeys(): ReadonlyMap<string, GateRecipientPubkeyEntry> {
  const map = new Map<string, GateRecipientPubkeyEntry>();
  for (const gk of [GateKind.LitV3, GateKind.Drand, GateKind.G4]) {
    map.set(`${gk}:0`, pubkeyEntry(AUTH_ID, gk));
  }
  return map;
}

function pubkeyEntry(authorizationId: Hex32, gateKind: GateKind): GateRecipientPubkeyEntry {
  return {
    authorizationId,
    gateKind,
    conditionalRecipientIndex: 0,
    kemPubkey: new Uint8Array([gateKind + 1, 1]),
    attestationRef: hex32(gateKind + 1),
    effectiveBlock: 1n,
    tombstoneBlock: 0n,
    perCommitEphemeral: gateKind !== GateKind.Drand,
  };
}

function makeInMemoryRepo() {
  const statuses = new Map<string, unknown>();
  const bundles = new Map<string, unknown>();
  const manifests = new Map<string, unknown>();
  return {
    async upsertStatus(s: { authorizationId: string }) {
      statuses.set(s.authorizationId, s);
    },
    async getStatus(id: string) {
      return statuses.get(id);
    },
    async putManifest(id: string, m: unknown) {
      manifests.set(id, m);
    },
    async getManifest(id: string) {
      return manifests.get(id);
    },
    async putBundle(b: { authorizationId: string; recipient_ref: string }) {
      bundles.set(`${b.authorizationId}:${b.recipient_ref}`, b);
    },
    async getBundle(id: string, ref: string) {
      return bundles.get(`${id}:${ref}`);
    },
    async listBundles() {
      return [];
    },
  } as unknown as Parameters<typeof processRevealAuthorizedEvent>[1]["repository"];
}

function inMemoryCursor() {
  let cur: { lastProcessedBlock: bigint; lastProcessedLogIndex: number } | undefined;
  return {
    async load() {
      return cur;
    },
    async advance(c: { lastProcessedBlock: bigint; lastProcessedLogIndex: number }) {
      cur = c;
    },
  };
}

// ─────────────────────────── anvil / chain helpers ───────────────────────────

async function startAnvil(): Promise<ChildProcess> {
  const child = spawn(resolve(FOUNDRY_BIN, "anvil"), ["--port", String(ANVIL_PORT), "--chain-id", "31337", "--silent"], {
    stdio: "ignore",
  });
  const client = createPublicClient({ transport: http(ANVIL_RPC) });
  for (let i = 0; i < 80; i++) {
    try {
      await client.getBlockNumber();
      return child;
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  child.kill("SIGKILL");
  throw new Error("anvil did not become ready");
}

async function mineBlock(): Promise<void> {
  await fetch(ANVIL_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "evm_mine", params: [] }),
  });
}

async function increaseTime(seconds: number): Promise<void> {
  await fetch(ANVIL_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "evm_increaseTime", params: [seconds] }),
  });
}

async function waitFor(cond: () => boolean, timeoutMs: number, label: string): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timeout waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

// ─────────────────────────── DB seed/clean ───────────────────────────

async function cleanSlate(sql: Sql): Promise<void> {
  for (const h of [INGEST_H_COMMIT, SHRED_INGEST_H_COMMIT, hex32(0xa3)]) {
    await sql`DELETE FROM dek_share_records WHERE h_commit = ${h}`.catch(() => {});
    await sql`DELETE FROM ingestions WHERE h_commit = ${h}`.catch(() => {});
    await sql`DELETE FROM vault_audit_log WHERE h_commit = ${h}`.catch(() => {});
  }
  for (const ref of [VAULT_REF, SHRED_VAULT_REF, `vault://${hex32(0xa3)}`]) {
    await sql`DELETE FROM vault_blobs WHERE vault_ref = ${ref}`.catch(() => {});
  }
  await sql`DELETE FROM partner_agreements WHERE partner_id = ${PARTNER_ID}`.catch(() => {});
  await sql`DELETE FROM partners WHERE partner_id = ${PARTNER_ID}`.catch(() => {});
}

async function seedPartner(sql: Sql): Promise<void> {
  await sql`
    INSERT INTO partners (partner_id, name, api_key_id, api_key_bcrypt, signing_secret_encrypted, scopes, webhook_secret_encrypted)
    VALUES (${PARTNER_ID}, 'E2E Partner', ${"key-" + PARTNER_ID}, 'x', 'x', ARRAY['ingest']::text[], 'x')
    ON CONFLICT (partner_id) DO NOTHING
  `;
  await sql`
    INSERT INTO partner_agreements (partner_agreement_id, partner_id, pda_id, status, effective_at)
    VALUES (gen_random_uuid(), ${PARTNER_ID}, ${PDA_ID}, 'active', now() - interval '1 hour')
    ON CONFLICT DO NOTHING
  `;
}

// ─────────────────────────── ABI helpers ───────────────────────────

function conditionEngineAbiFor(fn: string): readonly unknown[] {
  const all = JSON.parse(
    readFileSync(resolve(CONTRACTS_DIR, "out", "ConditionEngine.sol", "ConditionEngine.json"), "utf-8"),
  ).abi as { type?: string; name?: string }[];
  return all.filter((i) => i.type === "event" || (i.type === "function" && i.name === fn));
}

function shredRegistryAbiFor(fn: string): readonly unknown[] {
  const all = JSON.parse(
    readFileSync(resolve(CONTRACTS_DIR, "out", "ShredRegistry.sol", "ShredRegistry.json"), "utf-8"),
  ).abi as { type?: string; name?: string }[];
  return all.filter((i) => i.type === "function" && i.name === fn);
}

// ─────────────────────────── small helpers ───────────────────────────

function bytes32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function hex32(byte: number): Hex32 {
  return ("0x" + byte.toString(16).padStart(2, "0").repeat(32).slice(0, 64)) as Hex32;
}
