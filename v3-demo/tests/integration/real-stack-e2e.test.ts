// REAL-STACK E2E (Phase 4 → F-WRAP-1 fix verification, env-gated
// INTEGRATION_REAL_STACK=1).
//
// PURPOSE
// -------
// Drive the V3 escrow→reveal path against REAL infra — real Postgres
// (`cealis_v3_test`), the real Postgres vault backend, the real DEK dealer
// (`dealDek`), the real §6.2 per-gate hybrid-PQ WRAP at ingest, the real
// `dek_share_records` table, the real `ProductionSigmaGatherer`, the real
// per-gate UNWRAP at reveal, and the REAL combiner (`combineAndDecrypt`). The
// only doubles are the §6 vendor gate σ-signing clients (the base
// `StubGateSigningClient`s the composition root also wires locally) — the
// cryptographic wrap → store → unwrap → combine → decrypt path is REAL.
//
// THE NON-CUSTODY FIX THIS TEST PROVES
// ------------------------------------
// PREVIOUSLY: `dealDek` produced RAW Shamir shares which the writer persisted RAW
// to `dek_share_records`. The server alone held enough to reconstruct the DEK —
// a violation of the 4-gate-AND non-custody threat model.
//
// NOW: each dealt share is hybrid-PQ-WRAPPED to ITS gate's recipient pubkey
// (§6.2) and stored ONLY wrapped. At reveal each gate unwraps ONLY its own stanza
// with ITS private key (local stand-in for the gate enclave) → returns its share
// in σ evidence → the combiner gathers the threshold of shares → reconstructs the
// DEK → AEAD-decrypts. The 3 blocks prove:
//   (a) ESCROW: real wrap → only WRAPPED material lands in dek_share_records + vault.
//   (b) REVEAL: the production path (gather → unwrap → combine → decrypt) recovers
//       the EXACT ingested plaintext, with an anvil block as the on-chain trigger.
//   (c) ADVERSARIAL (load-bearing): the server's FULL durable DB state (vault blob
//       + every dek_share_records row), WITHOUT the gate private keys, CANNOT
//       reconstruct the DEK — proving no single party (not even the server holding
//       the whole DB) can open it.
//
// Run: INTEGRATION_REAL_STACK=1 CEALIS_V3_DATABASE_URL=postgres://localhost:5432/cealis_v3_test \
//        pnpm -F @cealis/v3-demo exec vitest run tests/integration/real-stack-e2e.test.ts

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { createPublicClient, http } from "viem";
import postgres, { type Sql } from "postgres";

/** The migrations live as .sql next to the v3-api source (not copied to dist). */
const MIGRATIONS_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "v3-api",
  "src",
  "db",
  "migrations",
);

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

import {
  GateKind,
  measureRunningCombinerBundle,
  type GateRecipientPubkeyEntry,
} from "@cealis/v3-custody";

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

import type {
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "@cealis/v3-custody";

import {
  RealVaultWriter,
  LocalGateKeyStore,
  PostgresWrappedShareStore,
  UnwrappingGateSigningClient,
  makeWrappedStanzaLoader,
  type GateRecipientKeyProvider,
  type HCommitArtifacts,
  type IngestContextResolver,
  type SealerPort,
  type SealOutput,
} from "@cealis/v3-api/runtime";

import {
  encodeCommitAAD,
  encryptPayload,
  zeroCommitAADInput,
} from "@cealis/v3-crypto";

const REAL = process.env["INTEGRATION_REAL_STACK"] === "1";
const PG_URL =
  process.env["CEALIS_V3_DATABASE_URL"] ?? process.env["V3_TEST_PG_URL"] ?? "";
const describeReal = REAL && PG_URL ? describe : describe.skip;

const ANVIL_PORT = 8546;
const ANVIL_RPC = `http://127.0.0.1:${ANVIL_PORT}`;

const AUTH_ID = hex32(0x11);
const H_COMMIT = hex32(0x22);
const VAULT_REF = `vault://${H_COMMIT}`;
const CANONICAL_CHAIN_ID = 84_532; // the combiner's pre-verify pin checks the snapshot chainId
const CANONICAL_CONDITION_ENGINE = "0xb09a8300423CA3BD0E028bAB6A6245A248520D02" as const;
const PROFILE: AccessStructureProfile = { kind: "FIXED_ONLY" };
const G3_CHOICE = "drand" as const;

const KNOWN_PLAINTEXT = {
  legal_name: "Ada Lovelace",
  date_of_birth: "1815-12-10",
  nationality: "GB",
} as const;

describeReal("REAL-STACK E2E — escrow→reveal against real Postgres + real crypto + anvil trigger", () => {
  let sql: Sql;
  let vault: CealisV3Vault;
  let anvil: ChildProcess | undefined;
  const gateKeyStore = new LocalGateKeyStore();

  beforeAll(async () => {
    sql = postgres(PG_URL, { max: 4, onnotice: () => {} });
    await applyMigrations(sql, MIGRATIONS_DIR);
    vault = new CealisV3VaultImpl({ store: new PostgresVaultStore({ sql }) });
    // Clean slate for this h_commit (idempotent reruns).
    await sql`DELETE FROM dek_share_records WHERE h_commit = ${H_COMMIT}`.catch(() => {});
    await sql`DELETE FROM vault_blobs WHERE vault_ref = ${VAULT_REF}`.catch(() => {});

    anvil = await startAnvil();
  }, 60_000);

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

  // ── (a) ESCROW: real seal → real deal → real WRAP-to-gate → store to real PG ──
  it("ESCROW: persists ONLY WRAPPED stanzas (no raw share) + the age envelope to real Postgres", async () => {
    const writer = makeWriter(gateKeyStore, sql, vault);
    const result = await writer.write({
      h_commit: H_COMMIT,
      plaintext: new TextEncoder().encode(JSON.stringify(KNOWN_PLAINTEXT)),
      payload_classification: { contains_pii: true },
    });
    expect(result.vault_ref).toBe(VAULT_REF);

    // The vault stores the AGE ENVELOPE (wrapped stanzas + payload), not raw bytes.
    const blob = await vault.getBlob(VAULT_REF);
    const decoded = decodeAgeEnvelope(blob.ciphertext);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.stanzas).toHaveLength(3); // Lit, G3, G4
    // No plaintext at rest.
    expect(Buffer.from(blob.ciphertext).toString("utf8")).not.toContain("Ada Lovelace");

    // dek_share_records holds ONLY wrapped 1168-byte payloads — never a raw share.
    const rows = await sql<{ wrapped_payload: Buffer; gate_kind: number }[]>`
      SELECT wrapped_payload, gate_kind FROM dek_share_records
      WHERE h_commit = ${H_COMMIT} ORDER BY stanza_index
    `;
    expect(rows).toHaveLength(3);
    for (const r of rows) {
      expect(r.wrapped_payload.length).toBe(1168); // 32 + 1088 + 48 — not a 39-byte raw share
    }
    // The retired raw-share column does not exist.
    const cols = await sql<{ column_name: string }[]>`
      SELECT column_name FROM information_schema.columns WHERE table_name = 'dek_share_records'
    `;
    const names = cols.map((c) => c.column_name);
    expect(names).not.toContain("share_bytes");
    expect(names).toContain("wrapped_payload");
  });

  // ── (b) REVEAL (production path): gather σ → per-gate UNWRAP → combine → decrypt ──
  it("REVEAL (production wiring): gates unwrap their own stanza → combiner recovers the EXACT ingested plaintext", async () => {
    // The on-chain condition fires: an anvil block stands in for the
    // RevealAuthorized emission. We read a real block from anvil and bind the
    // reveal to it.
    const trigger = await readAnvilTrigger();

    // The σ-gatherer EXACTLY as the composition root builds it: real
    // ProductionSigmaGatherer over UnwrappingGateSigningClients that load each
    // gate's WRAPPED stanza from real Postgres and unwrap it with the gate's
    // PRIVATE key (held in the LocalGateKeyStore, NEVER in the DB).
    const unwrapSource = gateKeyStore.unwrapSource(makeWrappedStanzaLoader(sql));
    const wrapGate = (k: GateSigningClient["gateKind"]): GateSigningClient =>
      new UnwrappingGateSigningClient({ base: baseStubGate(k), source: unwrapSource });
    const clients: SigmaGatherClients = {
      lit: wrapGate(GateKind.LitV3),
      dcipher: wrapGate(GateKind.Dcipher),
      drand: wrapGate(GateKind.Drand),
      g4: wrapGate(GateKind.G4),
    };
    const sigmaGatherer = createProductionSigmaGatherer({
      clients,
      resolveContext: (req): SigmaGatherContext => stubSigmaContext(req, trigger.blockHash),
    });

    const repository = makeInMemoryRepo();
    const result = await processRevealAuthorizedEvent(makeRevealInput(trigger), {
      repository,
      sigmaGatherer,
      vault, // real PG vault — combiner reads the real age envelope from it
      now: () => new Date("2026-06-03T00:02:00.000Z"),
    });

    expect(result.status).toBe("finalized");
    expect(result.bundles).toHaveLength(1);
    // The combiner reconstructed the real DEK from the unwrapped shares and
    // AEAD-decrypted the real ciphertext → the ORIGINAL field values.
    const bundle = result.bundles[0]!;
    expect(bundle.plaintext.fields).toMatchObject({
      legal_name: KNOWN_PLAINTEXT.legal_name,
      nationality: KNOWN_PLAINTEXT.nationality,
    });
  });

  // ── (c) ADVERSARIAL non-custody assertion (the load-bearing test) ──
  it("ADVERSARIAL: the server's FULL durable DB state, WITHOUT the gate private keys, CANNOT reconstruct the DEK", async () => {
    // An attacker who has compromised the SERVER dumps EVERYTHING durable: the
    // vault blob (age envelope) + every dek_share_records row. The gate private
    // keys are NOT in the DB (they live only in the LocalGateKeyStore / gate
    // enclaves). We prove that, from durable state alone, the DEK is unreachable.

    // 1. Dump the vault age envelope.
    const blob = await vault.getBlob(VAULT_REF);
    const env = decodeAgeEnvelope(blob.ciphertext);
    expect(env.ok).toBe(true);

    // 2. Dump every dek_share_records row (the COMPLETE server share state).
    const rows = await sql<
      {
        stanza_index: number;
        binding_tag: string;
        gate_kind: number;
        conditional_recipient_index: number;
        domain: number;
        role: number;
        logical_index: number;
        x: number;
        wrapped_payload: Buffer;
        plugin_version_digest: Buffer;
        commit_context_digest_n: Buffer;
      }[]
    >`
      SELECT stanza_index, binding_tag, gate_kind, conditional_recipient_index, domain, role,
             logical_index, x, wrapped_payload, plugin_version_digest, commit_context_digest_n
      FROM dek_share_records WHERE h_commit = ${H_COMMIT} ORDER BY stanza_index
    `;
    expect(rows).toHaveLength(3);

    // 3a. Treating a wrapped payload AS IF it were a raw 32-byte share is
    //     structurally impossible — they are 1168 bytes, not 32. There is no
    //     reconstructable raw share anywhere in durable state.
    for (const r of rows) {
      expect(r.wrapped_payload.length).not.toBe(32);
      expect(r.wrapped_payload.length).not.toBe(39);
    }

    // 3b. The ONLY way to a share is to UNWRAP — and unwrapping requires the gate
    //     PRIVATE key, which the attacker (holding only the DB) does NOT have. We
    //     model the attacker's best move: mint fresh keypairs (or guess) and try
    //     to unwrap every stanza. EVERY unwrap fails — so ZERO shares are recovered.
    const { unwrapShareForRecipient } = await import("@cealis/v3-crypto");
    const recovered: ShareRecord[] = [];
    for (const r of rows) {
      const attackerKey = generateHybridWrapRecipientKeypair(); // NOT the gate's key
      const wrapped = decodeWrappedStanzaPayload(new Uint8Array(r.wrapped_payload));
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
        wrapped,
      });
      // Wrong key → AEAD/KEM failure. No share recovered.
      expect(out.ok).toBe(false);
      if (out.ok) recovered.push({} as ShareRecord);
    }
    expect(recovered).toHaveLength(0);

    // 3c. With ZERO recovered shares, Shamir.combine cannot reach threshold → the
    //     DEK is unreachable from durable state. (combineDek over an empty set
    //     fails the threshold/mandatory-branch check — never yields a DEK.)
    const combineEmpty = combineDek([], PROFILE);
    expect(combineEmpty.ok).toBe(false);

    // 4. POSITIVE CONTROL: the SAME wrapped stanzas DO reconstruct the DEK WHEN the
    //    real gate private keys (held outside the DB) are present — proving the
    //    failure above is genuinely the missing keys, not broken data.
    const realShares: ShareRecord[] = [];
    for (const r of rows) {
      const slot = { gateKind: r.gate_kind, conditionalRecipientIndex: r.conditional_recipient_index };
      const resolved = await gateKeyStore
        .unwrapSource(makeWrappedStanzaLoader(sql))
        .resolve({ authorizationId: AUTH_ID, hCommit: H_COMMIT, ...slot });
      const wrapped = decodeWrappedStanzaPayload(resolved.stanza.wrapped_payload);
      const out = unwrapShareForRecipient({
        stanza_index: resolved.stanza.stanza_index,
        binding_tag: resolved.stanza.binding_tag,
        plugin_version_digest: resolved.stanza.plugin_version_digest,
        commit_context_digest_N: resolved.stanza.commit_context_digest_N,
        share_domain: resolved.stanza.share_domain as never,
        share_role: resolved.stanza.share_role as never,
        logical_index: resolved.stanza.logical_index,
        x: resolved.stanza.x,
        recipient: resolved.recipient,
        wrapped,
      });
      expect(out.ok).toBe(true);
      if (out.ok) {
        realShares.push({
          share_domain: resolved.stanza.share_domain as ShareRecord["share_domain"],
          share_role: resolved.stanza.share_role as ShareRecord["share_role"],
          logical_index: resolved.stanza.logical_index,
          x: resolved.stanza.x,
          value: out.share,
        });
      }
    }
    const combineReal = combineDek(realShares, PROFILE);
    expect(combineReal.ok).toBe(true); // the keys-present path DOES reconstruct
  });
});

// ─────────────────────────── ingest wiring ───────────────────────────

function makeWriter(store: LocalGateKeyStore, sql: Sql, vault: CealisV3Vault): RealVaultWriter {
  const gateRecipientKeys: GateRecipientKeyProvider = store.recipientKeyProvider();
  const resolveContext: IngestContextResolver = {
    resolve: () => ({
      hCommit: buildHCommitArtifacts(),
      accessStructureProfile: PROFILE,
      retentionPolicyId: "obligation+3y",
      retentionExpiresAt: "2099-01-01T00:00:00.000Z",
      shredAuthority: "subject",
      vaultRef: VAULT_REF,
    }),
  };
  return new RealVaultWriter({
    sealer: realSealer(),
    vault,
    shareStore: new PostgresWrappedShareStore(sql),
    resolveContext,
    gateRecipientKeys,
  });
}

/** A sealer that mirrors the composition root's StubSealerPort: generate a DEK,
 *  AEAD-encrypt the plaintext, surface the inner ciphertext + digests. */
function realSealer(): SealerPort {
  return {
    seal(input): SealOutput {
      const dek = new Uint8Array(32);
      for (let i = 0; i < dek.length; i++) dek[i] = (i * 37 + 11) & 0xff;
      dek[0] = 0x5a;
      const commitContextDigest0 = commitContextDigest0Bytes();
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

function buildHCommitArtifacts(): HCommitArtifacts {
  return {
    authorizationId: AUTH_ID,
    h_commit: H_COMMIT,
    aad_digest: hex32(0x02),
    commit_context_digest: ("0x" + Buffer.from(commitContextDigest0Bytes()).toString("hex")) as Hex32,
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

function commitContextDigest0Bytes(): Uint8Array {
  return new Uint8Array(32).fill(0xaa);
}

// ─────────────────────────── anvil trigger ───────────────────────────

interface AnvilTrigger {
  readonly blockHash: Hex32;
  readonly blockNumber: bigint;
}

async function startAnvil(): Promise<ChildProcess> {
  const child = spawn("anvil", ["--port", String(ANVIL_PORT), "--chain-id", "31337", "--silent"], {
    stdio: "ignore",
  });
  // Wait until anvil answers a block-number RPC.
  const client = createPublicClient({ transport: http(ANVIL_RPC) });
  for (let i = 0; i < 60; i++) {
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

/** Mine an anvil block and read it — the real on-chain RevealAuthorized trigger. */
async function readAnvilTrigger(): Promise<AnvilTrigger> {
  const client = createPublicClient({ transport: http(ANVIL_RPC) });
  // Mine a block so the trigger is fresh.
  await fetch(ANVIL_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "evm_mine", params: [] }),
  });
  const block = await client.getBlock();
  return { blockHash: block.hash as Hex32, blockNumber: block.number };
}

// ─────────────────────────── reveal wiring ───────────────────────────

/** The base vendor-gate σ-signing double (mirror of the composition root's
 *  StubGateSigningClient) the UnwrappingGateSigningClient decorates. Produces a
 *  deterministic authorization σ + always-ok verify; the §6.2 unwrap is added by
 *  the decorator. */
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

function stubSigmaContext(request: SigmaGatheringRequest, blockHash: Hex32): SigmaGatherContext {
  const pubkeys = new Map<string, GateRecipientPubkeyEntry>();
  for (const gk of [GateKind.LitV3, GateKind.Drand, GateKind.G4]) {
    pubkeys.set(`${gk}:0`, pubkeyEntry(request.authorizationId, gk));
  }
  return {
    authorizationBlock: 20n,
    commitBlock: 10n,
    blockHash,
    profile: PROFILE,
    gateRecipientPubkeys: pubkeys,
  };
}

/** The commit-snapshot pubkey map the combiner cross-checks σ evidence against —
 *  identical entries to `stubSigmaContext` (gather + verify agree). */
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

function makeRevealInput(trigger: AnvilTrigger): EventDrivenRevealInput {
  return {
    event: {
      authorizationId: AUTH_ID,
      h_commit: H_COMMIT,
      pda_root: hex32(0x55),
      authorization_block: 20n,
      authorization_timestamp: 1_778_489_600n,
      challenge_window: 60,
      conditionRef: hex32(0x44),
      block_hash: trigger.blockHash,
      block_number: trigger.blockNumber,
    },
    partner_id: "11111111-1111-4111-8111-111111111111",
    pda: {
      pda_id: "22222222-2222-4222-8222-222222222222",
      pda_version: "e2e",
      trust_tier: "tier_b",
      operational_class: "regulated",
    },
    g3_choice: G3_CHOICE,
    g4_phase: 1,
    schema_digest: hex32(0x77),
    preconditions: {
      challenge_window_closed: true,
      shred_state_allows_reveal: true,
      registry_deprecation_acceptable: true,
      recipient_policy_identified: true,
    },
    combiner_input: {
      sigma_request: {
        authorizationId: AUTH_ID,
        h_commit: H_COMMIT,
        partner_id: "11111111-1111-4111-8111-111111111111",
        pda_id: "22222222-2222-4222-8222-222222222222",
        g3_choice: G3_CHOICE,
      },
      vault_ref: VAULT_REF,
      access_structure_profile: PROFILE,
      registry_snapshots: {
        commitSnapshot: {
          snapshot: { blockNumber: 10n, chainId: CANONICAL_CHAIN_ID, blockHash: hex32(0x10), observedAt: 1n },
          plugin: {
            pluginVersionDigest: hex32(0x44),
            // The combiner's plugin-integrity check binds the RUNNING combiner
            // bundle measurement; use the real measured value (as the production
            // commit snapshot would carry).
            binaryHashOrMeasurement: ("0x" + Buffer.from(measureRunningCombinerBundle()).toString("hex")) as Hex32,
            governanceMetadata: hex32(0x46),
            effectiveBlock: 1n,
            tombstoneBlock: 0n,
            deprecated: false,
          },
          // Must MATCH the gatherer-context pubkeys the σ evidence binds
          // (verifyGateRecipientPubkeys cross-checks σ.gateRecipientPubkey against
          // this map). Same entries as stubSigmaContext.
          gateRecipientPubkeys: commitSnapshotPubkeys(),
        } as EventDrivenRevealInput["combiner_input"]["registry_snapshots"]["commitSnapshot"],
        authorizationSnapshot: {
          snapshot: { blockNumber: 20n, chainId: CANONICAL_CHAIN_ID, blockHash: trigger.blockHash, observedAt: 2n },
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
      reveal_authorized_topics: [AUTH_ID, H_COMMIT, hex32(0x55)],
      receipt_proof: { proof_type: "mock_receipt", block_number: 20, block_hash: trigger.blockHash, log_index: 0 },
      commit_tx_hash: hex32(0x20),
      commit_block: 10,
      commit_block_hash: hex32(0x21),
      reveal_authorized_tx_hash: hex32(0x22),
      reveal_authorized_log_index: 0,
      reveal_authorized_block: 20,
      reveal_authorized_block_hash: trigger.blockHash,
      base_finality_confirmations: 32,
      conditionRef: hex32(0x44),
      shred_registry_state_at_reveal: "not_shredded",
    },
    registry_snapshots: { authorization_block: 20, authorization_block_hash: trigger.blockHash, registry_contracts: {} },
    shred_state: { h_commit: H_COMMIT, shred_state: "not_shredded", checked_at_block: 20, checked_at_block_hash: trigger.blockHash },
    sd_refs: { status: "not_configured", disclosure_refs: [] },
    gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
    registry_snapshot_refs: { authorization: trigger.blockHash },
    recipient_policy: { recipients: ["enforcement-endpoint"] },
    m3_scaffold: { artifact_type: "RevealArtifactBundle", authorizationId: AUTH_ID, hCommit: H_COMMIT },
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

// ─────────────────────────── small helpers ───────────────────────────

function bytes32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function hex32(byte: number): Hex32 {
  return ("0x" + byte.toString(16).padStart(2, "0").repeat(32).slice(0, 64)) as Hex32;
}
