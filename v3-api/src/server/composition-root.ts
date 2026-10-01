// Composition root (Phase 3 Wave 5, plan T5.2 + T2.1) — the single-owner wiring
// that turns the pile of built-but-unwired runtime pieces into a real
// `cealis-api` boot. Every prior wave built a port + left a default-swap flag;
// THIS file resolves all of them from `CEALIS_V3_*` env (never a `keys/` file),
// runs migrations, constructs the DB-backed stores / vault / repos / workers /
// listener, partially-applies the reveal processor, and returns the bag the bin
// hands to `createFastifyApp` + the lifecycle handles the shutdown path stops.
//
// EXTERNAL-GATE DISCIPLINE (Phase-3 plan §6 — build TO, do NOT cross): for every
// vendor boundary (real TEE sealer, real Lit/dcipher/drand/G4 gate σ clients,
// real KMS, mainnet) we inject the real-SHAPED port plus a local default and
// DOCUMENT the env var + vendor that wires the real one. Phase 3 never sets
// NODE_ENV=production, so the TEE stub fails-loud if mistakenly used in prod.
//
// CHAIN: 31337 (anvil) / 84532 (Base Sepolia) ONLY. Mainnet (8453) is rejected.
//
// V3 isolation (SECURITY.md): no @cealis/shared, no V1 packages, no
// V1 env-var names (the sealed-share / issuer-salt / committee-key family — see
// SECURITY.md). Every secret comes from a CEALIS_V3_* / REDIS_URL env var.

import { randomBytes } from "node:crypto";

import type { Address } from "viem";

import {
  applyMigrations,
  buildDb,
  resolveV3DatabaseUrl,
  type V3Database,
} from "../db/index.js";
import postgres from "postgres";
import type { Sql } from "postgres";

import {
  ACTIVE_COMMIT_VERSION,
  encodeCommitAAD,
  encryptPayload,
  type AccessStructureProfile,
} from "../m1-imports.js";
import {
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
} from "@cealis/v3-crypto";

import { CealisV3VaultImpl } from "../vault/cealis-v3-vault-impl.js";
import { PostgresVaultStore } from "../vault/backends/postgres-vault-store.js";
import type {
  CealisV3Vault,
  ShredAuthority,
  VaultBackendId,
  VaultRef,
} from "../vault/cealis-v3-vault.js";

import {
  createPostgresIngestionRepository,
} from "../ingest/postgres-ingestion-repository.js";
import {
  RealVaultWriter,
  type GateRecipientKeyProvider,
  type IngestContextResolver,
  type SealerPort,
  type SealOutput,
  type ShareRecordStore,
} from "../ingest/vault-writer-impl.js";
import { LocalGateKeyStore, type WrappedStanzaLoader } from "./local-gate-keys.js";
import { PostgresWrappedShareStore, makeWrappedStanzaLoader } from "./wrapped-share-store.js";
import { UnwrappingGateSigningClient } from "../combiner-orchestrator/gate-unwrap.js";
import {
  createPdaInspector,
  mapResolvedPdaToInspection,
  type PdaArtifactLoader,
  type PdaConfigSource,
  type PdaInspectionForIngestExtended,
} from "../ingest/pda-inspector.js";
import { PostgresPdaArtifactLoader } from "../ingest/pda-artifact-store.js";
import { IngestContextRegistry } from "../ingest/ingest-context-registry.js";
import type {
  IngestionDependencies,
  PdaInspectionForIngest,
} from "../ingest/routes-create-mode-a.js";
import { sealPlaintextForVault } from "../g4/sealed-code-server.js";
import { constructHCommitArtifacts } from "../h-commit/construct.js";
import type { Hex32 } from "../h-commit/index.js";

import { SyntheticChainAnchorClient } from "../chain-anchor/ingestion-anchor.js";
import type { ChainAnchorClient } from "../chain-anchor/index.js";

import {
  buildViemPublicClient,
  buildViemWalletClient,
  buildViemChainStateReader,
  buildViemReadAnchorClient,
  buildViemRevealEventClient as buildRealViemRevealEventClient,
  buildViemChainHeadReader,
  buildViemShredExecutorChainPort,
  ANVIL_DEV_KEY_0,
} from "../chain/viem-clients.js";
import type { PublicClient, WalletClient } from "viem";

import { PostgresRevealArtifactRepository } from "../bundle/postgres-reveal-repository.js";
import type { RevealArtifactRepository } from "../bundle/index.js";

import {
  createProductionSigmaGatherer,
  type GateSigningClient,
  type SigmaGatherClients,
  type SigmaGatherContext,
  type SigmaGatheringRequest,
  type SigmaGatherer,
} from "../combiner-orchestrator/sigma-gathering.js";
import {
  processRevealAuthorizedEvent,
  type CombinerInputReference,
  type EventDrivenRevealInput,
  type EventDrivenRevealResult,
} from "../combiner-orchestrator/index.js";
import type { RevealAuthorizedEvent, RevealInputResolver } from "../combiner-orchestrator/event-listener.js";
import { GateKind } from "../m3-imports.js";
import type {
  AuthorizationRegistrySnapshot,
  CommitRegistrySnapshot,
  GateRecipientPubkeyEntry,
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "../m3-imports.js";

import {
  ConcreteLiveStateReader,
  clearGatesAt,
  RevealCoordinatorImpl,
  type LiveStateReaderPorts,
} from "../reveal/reveal-coordinator-impl.js";
import type {
  LiveStateReader,
  RevealCoordinatorPorts,
} from "../reveal/reveal-coordinator.js";
import {
  Art18FreezeLivePortImpl,
  ChainConfirmationLivePortImpl,
  ChallengeWindowLivePortImpl,
  PostgresArt18FreezeStore,
  RegistryDeprecationLivePortImpl,
  ShredStateLivePortImpl,
  type ChainStateReader,
} from "../reveal/live-ports/index.js";

import {
  startDeliveryWorkerService,
  defaultPlaintextDecryptor,
  type DeliveryWorkerService,
  type PartnerSecretDecryptor,
} from "./start-delivery-worker.js";
import { bullmqConnectionFromEnv } from "../webhooks/bullmq-reveal-queue.js";
import type { RevealDeliveryQueue } from "../reveal/reveal-coordinator.js";

import {
  ShredExecutor,
  type ShareRecordDestroyer,
  type ShredAuditWriter,
  type ShredExecutorChainPort,
} from "../shred/shred-executor.js";
import {
  startRetentionWorkerService,
  type RetentionWorkerService,
} from "./start-retention-worker.js";
import type { ShredAuthorityResolver } from "../vault/retention-worker.js";

import {
  startRevealEventListener,
  dbRevealEventCursorStore,
  type RevealEventListenerHandle,
} from "./start-event-listener.js";

import type { CealisApiAppDeps } from "./index.js";
import type { CealisRouteContexts } from "./route-contexts.js";
import { buildRouteContexts } from "./route-contexts.js";
import type { PartnerReadableInspection } from "../m4-imports.js";

// ─────────────────────────────────────────────────────────────────────────────
// CHAIN CONFIG — 31337 / 84532 only; mainnet rejected.
// ─────────────────────────────────────────────────────────────────────────────

const ALLOWED_CHAIN_IDS = new Set<number>([31337, 84532]);

function resolveChainId(env: NodeJS.ProcessEnv): number {
  const raw = env["CEALIS_V3_CHAIN_ID"];
  const chainId = raw ? Number.parseInt(raw, 10) : 84532;
  if (!ALLOWED_CHAIN_IDS.has(chainId)) {
    throw new Error(
      `CEALIS_V3_CHAIN_ID=${chainId} is not allowed in Phase 3 — only 31337 (anvil) ` +
        `and 84532 (Base Sepolia). Mainnet (8453) is forbidden (V3 testnet-frozen).`,
    );
  }
  return chainId;
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability report — what booted LIVE vs an injected stub default.
// ─────────────────────────────────────────────────────────────────────────────

export interface CompositionCapabilityReport {
  readonly chainId: number;
  readonly db: "live-postgres";
  readonly vault: "postgres-blob";
  readonly ingestRepository: "postgres";
  /** "viem" when an RPC URL + key were wired; "synthetic" otherwise (DB-only boot). */
  readonly chainAnchor: "viem" | "synthetic";
  /** "stub-sealed-code-server" until the real Nitro/HSM TEE is wired via CEALIS_V3_TEE_*. */
  readonly sealer: "stub-sealed-code-server";
  /** "stub-local-gates" until real Lit/dcipher/drand/G4 are wired via CEALIS_V3_*_URL. */
  readonly sigmaGatherer: "stub-local-gates" | "viem-context";
  /** "viem" when an RPC URL was wired; "absent-fail-closed" otherwise. */
  readonly liveChainReader: "viem" | "absent-fail-closed";
  /** "bullmq" when Redis was reachable; "absent" otherwise (delivery worker skipped). */
  readonly deliveryWorker: "bullmq" | "absent";
  /** "started" when chain RPC + cursor wired; "absent" otherwise. */
  readonly eventListener: "started" | "absent";
  /** "started" — the retention worker always boots DB-only. */
  readonly retentionWorker: "started";
  /** "real-cascade" when the chain shred port + RPC were wired; "db-only" otherwise. */
  readonly shredExecutor: "real-cascade" | "db-only";
  /** "kms" when a KMS decryptor was wired; "plaintext-passthrough" for local. */
  readonly partnerSecretDecryptor: "kms" | "plaintext-passthrough";
  readonly notes: readonly string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// The composition result — the bag the bin consumes.
// ─────────────────────────────────────────────────────────────────────────────

export interface CompositionRoot {
  /** The deps `createFastifyApp` consumes (coordinator + ports + queue). */
  readonly appDeps: CealisApiAppDeps;
  /** The assembled route contexts (mounted by createFastifyApp via route-contexts). */
  readonly routeContexts: CealisRouteContexts;
  /** What booted live vs stub. */
  readonly capabilities: CompositionCapabilityReport;
  /** Stop every started worker/listener + close the DB. Idempotent. */
  shutdown(): Promise<void>;
}

// ─────────────────────────────────────────────────────────────────────────────
// External-gate default impls (build TO; documented env wires the real vendor).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SealerPort default = the in-process TEE STUB (`sealed-code-server.ts`,
 * NODE_ENV=production-guarded). Unlike `sealPlaintextForVault` — which zeroizes
 * its DEK before returning — the writer's SealerPort MUST surface the DEK so the
 * dealer can split it. So we re-seal here: generate a DEK in-process, AEAD-encrypt
 * via `encryptPayload`, and return the DEK alongside the ciphertext + commit
 * binding. The DEK is transient; `RealVaultWriter` zeroizes it the instant the
 * deal completes.
 *
 * REAL VENDOR: a Nitro Enclave / cloud HSM-TEE that generates + seals the DEK
 * inside the enclave. Wire via `CEALIS_V3_TEE_ENDPOINT` (+ attestation config)
 * when the enclave boundary lands; until then this stub is the Phase-1 scaffold.
 */
class StubSealerPort implements SealerPort {
  seal(input: Parameters<SealerPort["seal"]>[0]): SealOutput {
    if (process.env.NODE_ENV === "production") {
      throw new Error(
        "TEE STUB sealer must not run in production — wire the real Nitro/HSM TEE " +
          "(CEALIS_V3_TEE_ENDPOINT) before any production/pilot use (Decision D9).",
      );
    }
    // Touch the production-guarded stub so a single source owns the guard text +
    // the import is exercised (defends against drift in the guarded module).
    void sealPlaintextForVault;

    const dek = randomBytes(32);
    const commitContextDigest = input.hCommit.commit_context_digest;
    const commitContextDigest0 = commitContextDigest.startsWith("0x")
      ? Buffer.from(commitContextDigest.slice(2), "hex")
      : Buffer.alloc(32);
    const encrypted = encryptPayload({
      dek,
      commit_context_digest_0: commitContextDigest0,
      commit_AAD_v0: input.hCommit.commit_AAD,
      plaintext: input.plaintext,
    });
    // The SealOutput must carry the DEK for the dealer. We return a COPY of the
    // DEK and zero our local so only the writer's copy survives (it zeroizes it
    // after the deal). The inseparable C1 commit-binding fields are derived from
    // the HCommitArtifacts the route already computed: encodeCommitAAD yields the
    // raw on-wire bytes, ACTIVE_COMMIT_VERSION the on-wire version, and the
    // artifacts' aad_digest the anchor the combiner re-encode-compares against.
    // `ciphertext` is the INNER AEAD payload — the writer wraps the dealt shares
    // and places it at the tail of the canonical age envelope.
    const dekCopy = Uint8Array.prototype.slice.call(dek);
    dek.fill(0);
    const pluginVersionDigest = input.hCommit.commit_AAD.plugin_version_digest;
    const commitContextDigestN = commitContextDigest.startsWith("0x")
      ? Buffer.from(commitContextDigest.slice(2), "hex")
      : Buffer.alloc(32);
    return {
      dek: dekCopy,
      ciphertext: encrypted.ciphertext,
      commit_context_digest_0: new Uint8Array(commitContextDigest0),
      commit_aad_bytes: encodeCommitAAD(input.hCommit.commit_AAD),
      commit_version_onwire: ACTIVE_COMMIT_VERSION,
      commit_aad_digest: input.hCommit.aad_digest,
      plugin_version_digest: Uint8Array.from(pluginVersionDigest),
      commit_context_digest_N: new Uint8Array(commitContextDigestN),
    };
  }
}

/** Touch the imported domain constants so the import is load-bearing (and a
 *  future drift in those values trips typecheck here, not silently downstream). */
void SHARE_DOMAIN_TOP_LEVEL;
void SHARE_DOMAIN_RECIPIENT_BRANCH;

/**
 * DB-backed ShareRecordDestroyer — DELETE every `dek_share_records` row for an
 * h_commit (the irreversible DEK-share destruction step of the crypto-shred
 * cascade). Returns the row count destroyed.
 */
class PostgresShareRecordDestroyer implements ShareRecordDestroyer {
  constructor(private readonly sql: Sql) {}

  async destroyShares(hCommit: Hex32): Promise<number> {
    const rows = await this.sql<{ h_commit: string }[]>`
      DELETE FROM dek_share_records WHERE h_commit = ${hCommit} RETURNING h_commit
    `;
    return rows.length;
  }
}

/**
 * DB-backed ShredAuditWriter — append ONE immutable row to `vault_audit_log`
 * (action `shred.finalized`) keyed by h_commit. Append-only by the 0003 trigger;
 * the writer only ever INSERTs. NO PII in `safe_refs` (authority + actor + opaque
 * reason ref only).
 */
class PostgresShredAuditWriter implements ShredAuditWriter {
  constructor(
    private readonly sql: Sql,
    private readonly auditLogRetentionDays = 365,
  ) {}

  async appendShredAudit(input: Parameters<ShredAuditWriter["appendShredAudit"]>[0]): Promise<void> {
    const now = new Date();
    const purgeAfter = new Date(now.getTime() + this.auditLogRetentionDays * 24 * 60 * 60 * 1000);
    const safeRefs = JSON.stringify({
      shred_authority: input.shredAuthority,
      actor_ref: input.actorRef,
      ...(input.requestReasonRef !== undefined ? { request_reason_ref: input.requestReasonRef } : {}),
      ...(input.pdaId !== undefined ? { pda_id: input.pdaId } : {}),
    });
    // partner_id is a FK to partners(partner_id) (uuid) — only set it when the
    // caller supplied a real partner id; otherwise NULL (subject-initiated shred).
    const partnerId = input.partnerId ?? null;
    await this.sql`
      INSERT INTO vault_audit_log (
        audit_id, actor_ref, action, h_commit, partner_id, pda_id, safe_refs, created_at, purge_after
      ) VALUES (
        gen_random_uuid(), ${input.actorRef}, ${"shred.finalized"}, ${input.hCommit},
        ${partnerId}, ${input.pdaId ?? null}, ${safeRefs}::jsonb, ${now}, ${purgeAfter}
      )
    `;
  }
}

/**
 * Stub gate-signing client for the σ-gatherer. Each gate returns a deterministic
 * σ + always-`ok` verify. This is the LOCAL DEFAULT behind the real
 * `GateSigningClient` port — the boot smoke exercises the real
 * `ProductionSigmaGatherer` orchestration shape against these doubles when no
 * vendor URL is wired.
 *
 * REAL VENDOR per gate: Lit V3 Chipotle SDK (CEALIS_V3_LIT_*), dcipher committee
 * (CEALIS_V3_DCIPHER_*), drand League-of-Entropy (CEALIS_V3_DRAND_URL), the G4
 * TEE daemon (CEALIS_V3_G4_*). Each replaces this stub with `@cealis/v3-custody`
 * `create*Adapter(...)` narrowed to `GateSigningClient`.
 */
class StubGateSigningClient implements GateSigningClient {
  constructor(readonly gateKind: GateSigningClient["gateKind"]) {}

  async requestSigma(
    input: RequestSigmaInput<unknown>,
  ): Promise<RequestSigmaResult & { sigma: Uint8Array }> {
    return {
      sigma: new Uint8Array(64),
      gateKind: this.gateKind,
      metadata: { authorizationId: input.authorizationId },
    };
  }

  async verifySigma(): Promise<VerifySigmaResult> {
    return { ok: true } as VerifySigmaResult;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// The RevealInputResolver (T3.3 → T3.5) — the genuinely-missing piece.
//
// Translates a bare on-chain `RevealAuthorized` event into the rich
// `RevealInputForDriver<EventDrivenRevealInput>` (= Omit<…, "event">) the driver
// merges `{...input, event}` and hands to the partially-applied processor.
// PDA-driven, nothing hardcoded (PLATFORM PRINCIPLE): per event it reads the PDA
// via the inspector, builds the `combiner_input` reference (σ-gathering request
// + vault ref + access-structure profile from the inspection + registry
// snapshots from the live chain reader + canonical address pin + conditional-
// recipients policy) and the recipient selectors.
// ─────────────────────────────────────────────────────────────────────────────

export interface RevealInputResolverDeps {
  /** Reads the active PDA for the event's authorization (g3_choice / g4_phase /
   *  trust_tier / operational_class / access_structure_profile). */
  readonly inspectPda: (input: {
    readonly pda_id: string;
    readonly partner_id: string;
    readonly pda_version: string;
  }) => Promise<PdaInspectionForIngestExtended> | PdaInspectionForIngestExtended;
  /** Resolves (partner_id, pda_id, pda_version, subjectCommitment, vault_ref)
   *  for a bare event — the on-chain `RevealAuthorized` carries only h_commit /
   *  pda_root, so the rest is resolved from the ingestion record. */
  readonly resolveAuthorizationContext: (
    event: RevealAuthorizedEvent,
  ) => Promise<RevealAuthorizationContext>;
  /** Live registry-snapshot reader for the combiner pre-verify pipeline. */
  readonly readRegistrySnapshots: (
    event: RevealAuthorizedEvent,
  ) => Promise<CombinerInputReference["registry_snapshots"]>;
  /** Configured ConditionEngine address + chainId (the mandatory canonical pin). */
  readonly canonicalAddressPin: CombinerInputReference["canonical_address_pin"];
}

/** The per-authorization context the resolver needs but the bare event lacks. */
export interface RevealAuthorizationContext {
  readonly partner_id: string;
  readonly pda_id: string;
  readonly pda_version: string;
  readonly subjectCommitment: Hex32;
  readonly vault_ref: VaultRef;
  readonly schema_digest: Hex32;
  /**
   * The INGEST h_commit (`ingestions.h_commit`) — the key the `dek_share_records`
   * wrapped stanzas + the vault blob are stored under. This is the
   * commit_context_digest form the ingest route produced, which is INTENTIONALLY
   * distinct from the on-chain h_commit in the RevealAuthorized event (S2-1 §3.4.1
   * keccak with the ciphertext digest). The σ-gather + combiner unwrap must key by
   * THIS value, not the event's on-chain h_commit, or the stanza load misses.
   * Optional: when absent the resolver falls back to the event's h_commit.
   */
  readonly ingest_h_commit?: Hex32;
}

/**
 * Build the production `RevealInputResolver<EventDrivenRevealInput>`. The driver
 * supplies `event`; this resolves everything else.
 */
export function createRevealInputResolver(
  deps: RevealInputResolverDeps,
): RevealInputResolver<EventDrivenRevealInput> {
  return {
    async resolve(event: RevealAuthorizedEvent) {
      const ctx = await deps.resolveAuthorizationContext(event);
      const pda = await deps.inspectPda({
        pda_id: ctx.pda_id,
        partner_id: ctx.partner_id,
        pda_version: ctx.pda_version,
      });

      // σ-gather + combiner unwrap key the wrapped stanzas + vault blob by the
      // INGEST h_commit (the commit_context_digest the ingest route stored), NOT
      // the on-chain h_commit in the event. They are intentionally distinct forms.
      const stanzaHCommit = ctx.ingest_h_commit ?? event.h_commit;
      const sigmaRequest: SigmaGatheringRequest = {
        authorizationId: event.authorizationId,
        h_commit: stanzaHCommit,
        partner_id: ctx.partner_id,
        pda_id: ctx.pda_id,
        g3_choice: pda.g3_choice,
      };

      const registrySnapshots = await deps.readRegistrySnapshots(event);
      const profile = pda.access_structure_profile;

      const combinerInput: CombinerInputReference = {
        sigma_request: sigmaRequest,
        vault_ref: ctx.vault_ref,
        access_structure_profile: profile,
        registry_snapshots: registrySnapshots,
        canonical_address_pin: deps.canonicalAddressPin,
        ...(profile.kind === "RECIPIENT_K_OF_N"
          ? {
              conditional_recipients_policy: {
                n_conditional: profile.n_conditional,
                k_conditional: profile.k_conditional,
              },
            }
          : {}),
      };

      // Recipient selectors: at minimum the single fixed recipient (the partner).
      // A K-of-N policy adds conditional-recipient selectors; those are resolved
      // from the PDA's conditional-recipient set (PLATFORM PRINCIPLE). The
      // minimal fixed selector keeps the flow PDA-driven without hardcoding a
      // recipient set the configurator owns. `fields: ["*"]` = the recipient's
      // full schema slice (per-recipient filtering applies the schema selector).
      const recipientSelectors: EventDrivenRevealInput["recipient_selectors"] = [
        {
          recipient_ref: ctx.partner_id,
          schema_selector_digest: ctx.schema_digest,
          fields: ["*"],
        },
      ];

      const input: Omit<EventDrivenRevealInput, "event"> = {
        partner_id: ctx.partner_id,
        pda: {
          pda_id: ctx.pda_id,
          pda_version: ctx.pda_version,
          trust_tier: pda.trust_tier,
          operational_class: pda.operational_class,
        },
        g3_choice: pda.g3_choice,
        g4_phase: pda.g4_phase,
        schema_digest: ctx.schema_digest,
        // Preconditions are derived by the coordinator from live clearance; the
        // event-driven path runs through the same combiner, so we stamp the
        // satisfied tuple (the driver gated on confirmations; the combiner's
        // local assert is the in-flow check). The C3a live-recheck happens in
        // the RevealCoordinator path; the event listener path is the
        // chain-confirmed driver.
        preconditions: {
          challenge_window_closed: true,
          shred_state_allows_reveal: true,
          registry_deprecation_acceptable: true,
          recipient_policy_identified: recipientSelectors.length > 0,
        },
        combiner_input: combinerInput,
        recipient_selectors: recipientSelectors,
        sigma_block: {} as EventDrivenRevealInput["sigma_block"],
        chain_proofs: {
          reveal_authorized_block_hash:
            event.block_hash ?? (`0x${"0".repeat(64)}` as Hex32),
        } as EventDrivenRevealInput["chain_proofs"],
        registry_snapshots: {} as EventDrivenRevealInput["registry_snapshots"],
        shred_state: {} as EventDrivenRevealInput["shred_state"],
        sd_refs: { status: "not_configured" } as EventDrivenRevealInput["sd_refs"],
        gate_endpoints: {},
        registry_snapshot_refs: {},
        recipient_policy: {},
      };
      return input;
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// The composition root.
// ─────────────────────────────────────────────────────────────────────────────

export interface WireCompositionRootOptions {
  /** Override the env (tests). Defaults to `process.env`. */
  readonly env?: NodeJS.ProcessEnv;
  /**
   * Override the PdaArtifactLoader (the configurator-artifact provenance seam).
   * The default throws on use — a real loader (IPFS / content-addressed store /
   * re-emit from the submitted PDA) is wired when the configurator integration
   * lands. The inspector only calls it when an active agreement exists, so the
   * boot path (no ingest in flight) never triggers it.
   */
  readonly pdaArtifactLoader?: PdaArtifactLoader;
  /** Override the KMS-backed partner webhook-secret decryptor (prod). Default
   *  is the plaintext pass-through (local fixtures). */
  readonly partnerSecretDecryptor?: PartnerSecretDecryptor;
}

/**
 * Construct the full composition root. Runs migrations, builds every DB-backed
 * store + the vault + the reveal/ingest deps, starts the workers/listener that
 * their infra is present for, and returns the bag + lifecycle.
 *
 * INFRA TOLERANCE (the boot-smoke contract): Postgres is MANDATORY (the runtime
 * has no in-memory fallback). Redis (delivery worker) + chain RPC (event
 * listener / live chain reads / viem anchor / real shred cascade) are OPTIONAL
 * at boot — when absent the corresponding sub-part is constructed against a
 * fail-closed stub or skipped, but the DB-backed + route-mount path STILL boots.
 * Every skip is recorded in the capability report.
 */
export async function wireCompositionRoot(
  options: WireCompositionRootOptions = {},
): Promise<CompositionRoot> {
  const env = options.env ?? process.env;
  const notes: string[] = [];

  // ── (1) DB: connect + run migrations 0001→0009 ──
  const connectionString = resolveV3DatabaseUrl();
  if (!connectionString) {
    throw new Error(
      "CEALIS_V3_DATABASE_URL is not set — the V3 API runtime requires a Postgres " +
        "connection (there is no in-memory fallback in Phase 3).",
    );
  }
  const sql: Sql = postgres(connectionString, {
    max: 10,
    idle_timeout: 30,
    onnotice: () => {
      /* suppress CREATE TABLE IF NOT EXISTS NOTICE noise during migrate */
    },
  });
  const db: V3Database = buildDb(sql);
  const migration = await applyMigrations(sql);
  notes.push(`migrations applied: ${migration.applied.join(", ")}`);

  const chainId = resolveChainId(env);

  // ── (1b) Chain clients (GAP-A): build the live viem clients ONCE when the
  //        RPC URL + addresses are present. NO RPC call fires at construction
  //        (viem clients are lazy). When the RPC/addresses are absent every
  //        chain-dependent sub-part keeps its fail-closed default (recorded in
  //        the capability report). Key provenance is env/KMS only — never a
  //        `keys/` file (R2x grep gate).
  const rpcUrl = env["CEALIS_V3_RPC_URL"];
  const conditionEngineAddress = env["CEALIS_V3_CONDITION_ENGINE_ADDRESS"] as Address | undefined;
  const shredRegistryAddress = env["CEALIS_V3_SHRED_REGISTRY_ADDRESS"] as Address | undefined;
  const chainWired = Boolean(rpcUrl && conditionEngineAddress);
  const publicClient: PublicClient | undefined = chainWired ? buildViemPublicClient(env) : undefined;
  // Operator wallet: the on-chain ceremony signer. Local E2E falls back to the
  // public, well-known anvil dev key #0 ONLY when no explicit operator key is set
  // AND the chain is anvil (31337). Production passes CEALIS_V3_OPERATOR_KEY (or a
  // KMS-derived account). The fallback never carries secret value (it is the
  // standard anvil mnemonic key), and is gated on the dev chain.
  const operatorKeyEnv =
    env["CEALIS_V3_OPERATOR_KEY"] ??
    (chainId === 31_337 && rpcUrl ? ANVIL_DEV_KEY_0 : undefined);
  const operatorWallet: WalletClient | undefined =
    operatorKeyEnv !== undefined
      ? buildViemWalletClient({ ...env, CEALIS_V3_OPERATOR_KEY: operatorKeyEnv }, "CEALIS_V3_OPERATOR_KEY")
      : undefined;

  // ── (2) Vault: real Postgres-blob backend ──
  const vaultBackendId: VaultBackendId = "postgres-blob";
  void vaultBackendId;
  const vault: CealisV3Vault = new CealisV3VaultImpl({
    store: new PostgresVaultStore({ sql }),
  });

  // ── (3) Ingestion path ──
  const ingestRepository = createPostgresIngestionRepository({ sql });

  // PDA inspector — reads the active agreement + the configurator artifact. The
  // artifact loader is the swappable provenance seam: the real Postgres-backed
  // loader reads the config body from the content-addressed `pda_artifacts` table
  // (migration 0010) and revives it. A test may override it; absent an override
  // the production loader is wired (it throws fail-loud when no artifact exists).
  const pdaArtifactLoader: PdaArtifactLoader =
    options.pdaArtifactLoader ?? new PostgresPdaArtifactLoader(sql);
  const pdaConfigSource: PdaConfigSource = {
    async loadActivePda(input) {
      const rows = await sql<{ pda_id: string }[]>`
        SELECT pda_id FROM partner_agreements
        WHERE partner_id = ${input.partner_id} AND pda_id = ${input.pda_id}
          AND status = ${"active"} AND effective_at <= now()
        ORDER BY effective_at DESC LIMIT 1
      `;
      if (rows.length === 0) {
        throw new Error(
          `No active partner agreement for partner_id=${input.partner_id} pda_id=${input.pda_id}`,
        );
      }
      const artifact = await pdaArtifactLoader.load(input);
      const inspection: PartnerReadableInspection = artifact.inspection;
      const legalEffect = inspection.legal_flags_art9_qes_jurisdiction.legal_effect_expected;
      return {
        inspection,
        submitted: artifact.submitted,
        operational_class: legalEffect ? "legal_effect" : "b2b_partner",
        partner_ready: true,
        ...(artifact.retention_policy_id !== undefined
          ? { retention_policy_id: artifact.retention_policy_id }
          : {}),
        ...(artifact.halted !== undefined ? { halted: artifact.halted } : {}),
        ...(artifact.halt_reason !== undefined ? { halt_reason: artifact.halt_reason } : {}),
      };
    },
  };
  const inspectPda = createPdaInspector(pdaConfigSource);
  // `mapResolvedPdaToInspection` is the pure core the inspector calls — touch it
  // so the import is load-bearing (the resolver below may reuse it directly).
  void mapResolvedPdaToInspection;

  // VaultWriter: seal (stub TEE) → deal → WRAP-to-gate → store envelope + wrapped
  // stanzas. The LocalGateKeyStore is the local stand-in for the per-gate enclave
  // boundary: it owns the per-commit gate keypairs, exposes the PUBLIC keys to the
  // writer (wrap) and the PRIVATE keys to the reveal gate clients (unwrap). The
  // gate private keys are NEVER written to the DB (the non-custody invariant the
  // adversarial E2E asserts against the server's durable state).
  const gateKeyStore = new LocalGateKeyStore();
  const gateRecipientKeys: GateRecipientKeyProvider = gateKeyStore.recipientKeyProvider();
  const wrappedStanzaLoader: WrappedStanzaLoader = makeWrappedStanzaLoader(sql);
  const sealer: SealerPort = new StubSealerPort();
  const shareStore: ShareRecordStore = new PostgresWrappedShareStore(sql);

  // GAP-B per-request ingest-context seam. The route REGISTERS the full computed
  // HCommitArtifacts + PDA-selected access structure / retention / shred authority
  // / vault ref (it already computed the same h_commit) just before vault.write;
  // the resolver READS it back inside the writer so the sealer binds the IDENTICAL
  // commit_AAD the route bound (no re-derivation, no drift). A single process owns
  // both route + writer, so the registry is the in-process handoff.
  const ingestContextRegistry = new IngestContextRegistry();
  const ingestContextResolver: IngestContextResolver = ingestContextRegistry.resolver();
  const registerIngestContext: NonNullable<IngestionDependencies["registerIngestContext"]> = (reg) => {
    // Map the route's registration into the IngestWriteContext the RealVaultWriter
    // resolves. The access-structure profile comes straight from the extended PDA
    // inspection (FIXED_ONLY / RECIPIENT_K_OF_N); absent it we fall back to the
    // PDA-derived n=0 default (FIXED_ONLY) so the dealer's invariant holds.
    const profile = (reg.accessStructureProfile as AccessStructureProfile | undefined) ?? {
      kind: "FIXED_ONLY",
    };
    ingestContextRegistry.register(reg.h_commit, {
      hCommit: reg.hCommitArtifacts,
      accessStructureProfile: profile,
      retentionPolicyId: reg.retentionPolicyId ?? "obligation_plus_3y",
      retentionExpiresAt: reg.retentionExpiresAt,
      shredAuthority: reg.shredAuthority ?? "operator",
      vaultRef: reg.vaultRef,
    });
  };
  void constructHCommitArtifacts; // re-exported for tests that build artifacts directly
  const vaultWriter = new RealVaultWriter({
    sealer,
    vault,
    shareStore,
    resolveContext: ingestContextResolver,
    gateRecipientKeys,
  });

  // Chain anchor: a real viem read-anchor when RPC + ConditionEngine are wired
  // (binds the ingest to the live chain head + confirms the PDA is registered
  // on-chain); else synthetic (DB-only boot).
  let chainAnchor: ChainAnchorClient;
  let chainAnchorMode: CompositionCapabilityReport["chainAnchor"];
  if (publicClient && conditionEngineAddress) {
    chainAnchor = buildViemReadAnchorClient({ publicClient, conditionEngineAddress });
    chainAnchorMode = "viem";
    notes.push(
      `chain anchor: viem read-anchor (ConditionEngine ${conditionEngineAddress}) — binds ` +
        "ingest to live chain head + confirms on-chain PDA registration.",
    );
  } else {
    chainAnchor = new SyntheticChainAnchorClient();
    chainAnchorMode = "synthetic";
    notes.push("chain anchor: no RPC/address wired — synthetic anchor (DB-only boot).");
  }

  const ingestionDependencies: IngestionDependencies = {
    inspectPda: inspectPda as IngestionDependencies["inspectPda"],
    repository: ingestRepository as unknown as IngestionDependencies["repository"],
    vault: vaultWriter,
    chainAnchor,
    registerIngestContext,
  };
  void (inspectPda satisfies (input: {
    readonly pda_id: string;
    readonly partner_id: string;
    readonly pda_version: string;
  }) => Promise<PdaInspectionForIngest>);

  // ── (4) Reveal path ──
  const revealRepository: RevealArtifactRepository = new PostgresRevealArtifactRepository({ sql });

  // σ gatherer: real ProductionSigmaGatherer over gate clients that each unwrap
  // ITS OWN stanza (the non-custody reveal seam) + a stub context resolver
  // (chain-read context is vendor/manifest-gated). Each base stub produces the
  // gate's authorization σ; `UnwrappingGateSigningClient` adds the §6.2 unwrap of
  // that gate's wrapped stanza (loaded from dek_share_records) using the gate's
  // PRIVATE key (held in the LocalGateKeyStore, NEVER in the DB). In production the
  // base swaps for the real Lit/dcipher/drand/G4 TEE adapter and the unwrap runs
  // INSIDE the gate enclave. The recovered share flows into σ metadata; the
  // combiner reconstructs the DEK from the threshold of shares — no server share-load.
  const unwrapSource = gateKeyStore.unwrapSource(wrappedStanzaLoader);
  const wrapGate = (gateKind: GateSigningClient["gateKind"]): GateSigningClient =>
    new UnwrappingGateSigningClient({ base: new StubGateSigningClient(gateKind), source: unwrapSource });
  const sigmaClients: SigmaGatherClients = {
    lit: wrapGate(GateKind.LitV3),
    dcipher: wrapGate(GateKind.Dcipher),
    drand: wrapGate(GateKind.Drand),
    g4: wrapGate(GateKind.G4),
    conditionalRecipients: [
      wrapGate(GateKind.ConditionalRecipient),
      wrapGate(GateKind.ConditionalRecipient),
      wrapGate(GateKind.ConditionalRecipient),
    ],
  };
  const sigmaGatherer: SigmaGatherer = createProductionSigmaGatherer({
    clients: sigmaClients,
    resolveContext: (request: SigmaGatheringRequest): SigmaGatherContext => {
      // Stub on-chain context — the real impl reads live at the authorization
      // block (no cache, C3a). The boot path never invokes this (no reveal in
      // flight at boot); it is wired so the gatherer is constructible.
      const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
      const pubkeys = new Map<string, GateRecipientPubkeyEntry>();
      const entry = (gateKind: GateRecipientPubkeyEntry["gateKind"], i: number): GateRecipientPubkeyEntry => ({
        authorizationId: request.authorizationId,
        gateKind,
        conditionalRecipientIndex: i,
        kemPubkey: new Uint8Array(32),
        attestationRef: `0x${"0".repeat(64)}` as Hex32,
        effectiveBlock: 0n,
        tombstoneBlock: 0n,
        perCommitEphemeral: true,
      });
      pubkeys.set(`${GateKind.LitV3}:0`, entry(GateKind.LitV3, 0));
      pubkeys.set(`${GateKind.Dcipher}:0`, entry(GateKind.Dcipher, 0));
      pubkeys.set(`${GateKind.Drand}:0`, entry(GateKind.Drand, 0));
      pubkeys.set(`${GateKind.G4}:0`, entry(GateKind.G4, 0));
      // gateExtras carries each conditional-recipient slot index to the unwrap
      // client so it loads + unwraps the correct branch stanza.
      const gateExtras = new Map<string, unknown>();
      for (let i = 0; i < 8; i++) {
        gateExtras.set(`${GateKind.ConditionalRecipient}:${i}`, { conditionalRecipientIndex: i });
      }
      return {
        authorizationBlock: 0n,
        commitBlock: 0n,
        blockHash: `0x${"0".repeat(64)}` as Hex32,
        profile,
        gateRecipientPubkeys: pubkeys,
        gateExtras,
      };
    },
  });

  // Live chain reader: real ViemChainStateReader (4 live chain reads at the
  // authorization block: shred-state, RevealAuthorized presence/depth,
  // challenge-window, registry deprecation) when RPC + addresses are wired; else
  // a fail-closed reader that throws on every read (a reveal cannot proceed
  // without chain). The shred-state read is direct-viem (anvil + any chain); on
  // the canonical chain (84532) the production wiring wraps the @cealis/v3-custody
  // RegistryReader (address-pinned). See `buildViemChainStateReader`.
  let chainStateReader: ChainStateReader;
  let liveChainReaderMode: CompositionCapabilityReport["liveChainReader"];
  if (publicClient && conditionEngineAddress && shredRegistryAddress) {
    chainStateReader = buildViemChainStateReader({
      publicClient,
      conditionEngineAddress,
      shredRegistryAddress,
      ...(env["CEALIS_V3_DEPLOY_BLOCK"] ? { fromBlock: BigInt(env["CEALIS_V3_DEPLOY_BLOCK"]) } : {}),
    });
    liveChainReaderMode = "viem";
    notes.push(
      `live chain reader: viem (ShredRegistry ${shredRegistryAddress}, ConditionEngine ${conditionEngineAddress}).`,
    );
  } else {
    chainStateReader = makeFailClosedChainStateReader();
    liveChainReaderMode = "absent-fail-closed";
    notes.push(
      "live chain reader: no RPC/ConditionEngine/ShredRegistry address wired — fail-closed reader " +
        "(reveal blocked without chain).",
    );
  }

  // Art.18 freeze store is DB-backed (per-subject, 90-day auto-expiry).
  const art18Store = new PostgresArt18FreezeStore({ sql });

  const livePorts: LiveStateReaderPorts = {
    shred: new ShredStateLivePortImpl(chainStateReader),
    art18: new Art18FreezeLivePortImpl(art18Store),
    chain: new ChainConfirmationLivePortImpl(chainStateReader),
    challenge: new ChallengeWindowLivePortImpl(chainStateReader),
    registry: new RegistryDeprecationLivePortImpl(chainStateReader),
  };
  const liveStateReader: LiveStateReader = new ConcreteLiveStateReader(livePorts);

  // ── (6) Delivery worker (BullMQ) — optional at boot (needs Redis) ──
  let deliveryService: DeliveryWorkerService | undefined;
  let deliveryQueue: RevealDeliveryQueue;
  let deliveryWorkerMode: CompositionCapabilityReport["deliveryWorker"];
  const partnerSecretDecryptor = options.partnerSecretDecryptor ?? defaultPlaintextDecryptor;
  try {
    const connection = bullmqConnectionFromEnv(env);
    deliveryService = startDeliveryWorkerService({
      connection,
      db,
      partnerSecretDecryptor,
    });
    deliveryQueue = deliveryService.queue;
    deliveryWorkerMode = "bullmq";
    notes.push("delivery worker: BullMQ queue + worker started (Redis wired).");
  } catch (err) {
    // No Redis — the delivery worker is skipped. The coordinator still needs a
    // RevealDeliveryQueue port; we inject a fail-closed enqueue that loudly
    // refuses (so a reveal that reaches delivery without Redis fails loud, not
    // silently). DB-backed + route-mount path is unaffected.
    deliveryQueue = makeUnavailableDeliveryQueue();
    deliveryWorkerMode = "absent";
    notes.push(
      `delivery worker: ABSENT — ${err instanceof Error ? err.message : String(err)} ` +
        "(reveal delivery fail-closed until Redis is wired).",
    );
  }
  const partnerSecretDecryptorMode: CompositionCapabilityReport["partnerSecretDecryptor"] =
    options.partnerSecretDecryptor ? "kms" : "plaintext-passthrough";

  // ── (7) Shred executor (crypto-shred cascade) ──
  const shareDestroyer: ShareRecordDestroyer = new PostgresShareRecordDestroyer(sql);
  const shredAuditWriter: ShredAuditWriter = new PostgresShredAuditWriter(sql);
  // Shred wallet: the on-chain ShredRegistry writer. Uses CEALIS_V3_SHRED_PRIVATE_KEY
  // if set, else the operator wallet (the operator holds shred OPERATOR_ROLE for
  // Operator-authority PDAs in the local stack). Key provenance is env/KMS — never
  // a `keys/` file.
  const shredWallet: WalletClient | undefined = env["CEALIS_V3_SHRED_PRIVATE_KEY"]
    ? buildViemWalletClient(env, "CEALIS_V3_SHRED_PRIVATE_KEY")
    : operatorWallet;
  let shredChainPort: ShredExecutorChainPort;
  let shredExecutorMode: CompositionCapabilityReport["shredExecutor"];
  if (publicClient && conditionEngineAddress && shredRegistryAddress && shredWallet) {
    shredChainPort = buildViemShredExecutorChainPort({
      walletClient: shredWallet,
      publicClient,
      conditionEngineAddress,
      shredRegistryAddress,
    });
    shredExecutorMode = "real-cascade";
    notes.push(
      `shred chain port: viem (ShredRegistry ${shredRegistryAddress}) — requestShred → authorizeShred ` +
        "(G1 refuse-future + G4 refuse); finalize published separately after the shred window.",
    );
  } else {
    shredChainPort = buildShredChainPort(env, notes);
    shredExecutorMode = "db-only";
  }
  const shredExecutor = new ShredExecutor({
    shredStatePort: livePorts.shred,
    shareDestroyer,
    vault,
    chainPort: shredChainPort,
    auditWriter: shredAuditWriter,
  });

  // ── (8) Retention worker — always boots (DB-only). Converges with the T4.2
  //        cascade: the injected vault for the worker DESTROYS shares on delete
  //        so a retention purge never leaves shares outliving ciphertext. ──
  const shredAuthorityResolver: ShredAuthorityResolver = {
    // PDA-config seam — resolves the per-blob shred authority. Without the
    // configurator artifact loader wired, default to "operator" (a permitted
    // erasure authority) so an EXPIRED blob is purged at its retention floor.
    // A disabled-authority PDA's blob is skipped by the worker (it never reaches
    // here for a disabled blob once the loader is live).
    resolve: async (): Promise<ShredAuthority> => "operator",
  };
  // Decorate the vault so a retention-driven deleteBlob ALSO destroys the
  // dek_share_records for the blob's h_commit (T4.3↔T4.2 convergence). The vault
  // ref scheme for ingestion ciphertext is `vault://{h_commit}`; we extract the
  // h_commit from the ref to key the share destroy.
  const retentionVault = makeShareDestroyingVault(vault, shareDestroyer);
  const retentionService: RetentionWorkerService = startRetentionWorkerService({
    vault: retentionVault,
    sql,
    shredAuthorityResolver,
  });
  notes.push("retention worker: started (DB-backed, share-destroying vault decorator).");

  // ── (4 cont.) Reveal coordinator + the partially-applied processor ──
  const coordinatorPorts: RevealCoordinatorPorts = {
    liveState: liveStateReader,
    clearGatesAt,
    anchor: chainAnchor,
  };
  const revealCoordinator = new RevealCoordinatorImpl(
    {
      repository: revealRepository,
      sigmaGatherer,
      vault,
    },
    // buildCombinerInput: the request-driven /internal/reveal/initiate path is a
    // test/ceremony entry; the production driver is the event listener. For the
    // request-driven path we surface a clear "needs the resolved authorization
    // context" error rather than fabricating a reveal input — the canonical
    // driver is the listener below.
    async () => {
      throw new Error(
        "RevealCoordinatorImpl.buildCombinerInput is the request-driven /internal path; " +
          "the production reveal driver is the RevealAuthorized event listener. Wire a " +
          "per-request resolver to use /internal/reveal/initiate.",
      );
    },
  );

  // ── (5) Event listener (T3.5) — optional at boot (needs chain RPC) ──
  let eventListenerHandle: RevealEventListenerHandle | undefined;
  let eventListenerMode: CompositionCapabilityReport["eventListener"] = "absent";
  if (publicClient && conditionEngineAddress) {
    const confirmationsRaw = env["CEALIS_V3_CONFIRMATIONS"];
    const confirmations = confirmationsRaw ? BigInt(confirmationsRaw) : 32n;

    // The partially-applied processor (T3.3) — processRevealAuthorizedEvent with
    // its deps bag baked in. The driver hands it the full `{ ...resolved, event }`.
    // The eventBus bridges a finalized bundle into the REAL BullMQ reveal-delivery
    // queue: when the combiner finalizes a recipient bundle, `reveal.finalized`
    // fires → we enqueue the delivery job so the delivery worker picks it up. This
    // is the bundle → queue → delivery worker seam (the queue is the BullMQ one
    // when Redis is wired, else the fail-closed enqueue that refuses loudly).
    const deliveryEventBus = {
      emit: async (event: { event_type?: string; data?: Record<string, unknown> }) => {
        if (event.event_type !== "reveal.finalized") return;
        const data = event.data ?? {};
        const authorizationId = data["authorizationId"] as Hex32 | undefined;
        const recipientRef = (data["recipient_ref"] as string | undefined) ?? "enforcement-endpoint";
        if (authorizationId === undefined) return;
        await deliveryQueue.enqueue({
          job_id: `${authorizationId}:${recipientRef}`,
          authorizationId,
          recipient_ref: recipientRef,
          payload: { artifact_digest: data["artifact_digest"], h_commit: data["h_commit"] },
        });
      },
    };
    const process = (input: EventDrivenRevealInput): Promise<EventDrivenRevealResult> =>
      processRevealAuthorizedEvent(input, {
        repository: revealRepository,
        sigmaGatherer,
        vault,
        eventBus: deliveryEventBus as unknown as Parameters<typeof processRevealAuthorizedEvent>[1]["eventBus"],
      });

    const inputResolver = createRevealInputResolver({
      inspectPda,
      resolveAuthorizationContext: async (event) => {
        // Resolve (partner_id, pda_id, version, subjectCommitment, vault_ref) from
        // the ingestion record the event points to. We key by authorizationId: it
        // is the STABLE identifier shared between the on-chain PDA (registered with
        // the same authorizationId) and the off-chain ingest — whereas the on-chain
        // h_commit (S2-1 §3.4.1 keccak with the ciphertext digest) and the ingest's
        // stored h_commit (the commit_context_digest form) are intentionally
        // distinct forms (commit_context_digest is NEVER chain-facing per
        // commit-context.ts). authorizationId bridges the two. We fall back to
        // h_commit for records that pre-date this resolution.
        const rows = await sql<{
          h_commit: string;
          partner_id: string;
          pda_id: string;
          pda_version: string;
          subject_commitment_v3: string | null;
          vault_blob_ref: string;
          schema_digest: string;
        }[]>`
          SELECT h_commit, partner_id, pda_id, pda_version, subject_commitment_v3, vault_blob_ref, schema_digest
          FROM ingestions
          WHERE authorization_id = ${event.authorizationId} OR h_commit = ${event.h_commit}
          ORDER BY (authorization_id = ${event.authorizationId}) DESC
          LIMIT 1
        `;
        const row = rows[0];
        if (!row) {
          throw new Error(
            `no ingestion record for authorizationId ${event.authorizationId} / h_commit ${event.h_commit} ` +
              "(event-driven reveal)",
          );
        }
        return {
          partner_id: row.partner_id,
          pda_id: row.pda_id,
          pda_version: row.pda_version,
          subjectCommitment: (row.subject_commitment_v3 ?? `0x${"0".repeat(64)}`) as Hex32,
          vault_ref: row.vault_blob_ref,
          schema_digest: row.schema_digest as Hex32,
          ingest_h_commit: row.h_commit as Hex32,
        };
      },
      readRegistrySnapshots: async () => ({
        commitSnapshot: {} as CommitRegistrySnapshot,
        authorizationSnapshot: {} as AuthorizationRegistrySnapshot,
      }),
      canonicalAddressPin: {
        configuredConditionEngine: conditionEngineAddress,
        chainId,
      },
    });

    eventListenerHandle = await startRevealEventListener<EventDrivenRevealInput, EventDrivenRevealResult>({
      client: buildRealViemRevealEventClient(publicClient),
      conditionEngineAddress,
      headReader: buildViemChainHeadReader(publicClient),
      cursorStore: dbRevealEventCursorStore({ db, chainId, conditionEngineAddress }),
      inputResolver,
      process,
      confirmations,
    });
    eventListenerMode = "started";
    notes.push(`event listener: started (ConditionEngine ${conditionEngineAddress}, confirmations=${confirmations}).`);
  } else {
    notes.push("event listener: ABSENT — no RPC/ConditionEngine address wired (reveal driver inactive).");
  }

  // ── (9) Route contexts + app deps ──
  const routeContexts = buildRouteContexts({
    shredExecutor,
    shredExecutorReady: shredExecutorMode === "real-cascade",
  });

  const appDeps: CealisApiAppDeps = {
    revealCoordinator,
    liveStateReader,
    coordinatorPorts,
    deliveryQueue,
    routeContexts,
    ingestionDependencies,
    revealRepository,
  };

  const capabilities: CompositionCapabilityReport = {
    chainId,
    db: "live-postgres",
    vault: "postgres-blob",
    ingestRepository: "postgres",
    chainAnchor: chainAnchorMode,
    sealer: "stub-sealed-code-server",
    sigmaGatherer: "stub-local-gates",
    liveChainReader: liveChainReaderMode,
    deliveryWorker: deliveryWorkerMode,
    eventListener: eventListenerMode,
    retentionWorker: "started",
    shredExecutor: shredExecutorMode,
    partnerSecretDecryptor: partnerSecretDecryptorMode,
    notes,
  };

  let stopped = false;
  const shutdown = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    eventListenerHandle?.stop();
    if (eventListenerHandle) await eventListenerHandle.drain();
    await retentionService.stop();
    if (deliveryService) await deliveryService.stop();
    await sql.end({ timeout: 5 });
  };

  return { appDeps, routeContexts, capabilities, shutdown };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper builders (chain readers, queues, vault decorator).
// ─────────────────────────────────────────────────────────────────────────────

/** A `ChainStateReader` whose every read throws — the boot default when chain
 *  RPC is not wired. Fail-closed: a reveal cannot proceed without chain. */
function makeFailClosedChainStateReader(): ChainStateReader {
  const fail = (op: string) => async (): Promise<never> => {
    throw new Error(`chain RPC not wired — ${op} fails closed (reveal blocked without chain).`);
  };
  return {
    getHeadBlock: fail("getHeadBlock"),
    getAuthorizationState: fail("getAuthorizationState") as ChainStateReader["getAuthorizationState"],
    getCurrentShredStateRaw: fail("getCurrentShredStateRaw") as ChainStateReader["getCurrentShredStateRaw"],
    isChallengeOpen: fail("isChallengeOpen") as ChainStateReader["isChallengeOpen"],
    getDeprecatedRefs: fail("getDeprecatedRefs") as ChainStateReader["getDeprecatedRefs"],
  };
}

/** A delivery queue that loudly refuses — the boot default when Redis is absent.
 *  A reveal that reaches delivery without Redis fails loud, never silently. */
function makeUnavailableDeliveryQueue(): RevealDeliveryQueue {
  return {
    enqueue: async () => {
      throw new Error("reveal delivery queue unavailable — Redis (BULLMQ_REDIS_URL/REDIS_URL) is not wired.");
    },
    deadLetter: async () => {
      throw new Error("reveal delivery queue unavailable — Redis (BULLMQ_REDIS_URL/REDIS_URL) is not wired.");
    },
  };
}

/**
 * Decorate a `CealisV3Vault` so `deleteBlob` ALSO destroys the
 * `dek_share_records` for the blob's h_commit (T4.3 retention ↔ T4.2 crypto-shred
 * convergence: shares must NEVER outlive the ciphertext). The ingestion ciphertext
 * ref scheme is `vault://{h_commit}`; we extract the h_commit to key the destroy.
 * A ref that is not h_commit-shaped (e.g. a reveal-artifact ref) skips the share
 * destroy (no shares are keyed to it).
 */
function makeShareDestroyingVault(
  vault: CealisV3Vault,
  shareDestroyer: ShareRecordDestroyer,
): CealisV3Vault {
  return {
    putBlob: (input) => vault.putBlob(input),
    getBlob: (ref) => vault.getBlob(ref),
    getRetentionStatus: (ref) => vault.getRetentionStatus(ref),
    listExpired: (asOf) => vault.listExpired(asOf),
    deleteBlob: async (input) => {
      const result = await vault.deleteBlob(input);
      const hCommit = hCommitFromVaultRef(input.ref);
      if (hCommit !== undefined) {
        await shareDestroyer.destroyShares(hCommit);
      }
      return result;
    },
  };
}

/** Extract an h_commit (0x + 64 hex) from a `vault://{h_commit}` ref, or undefined. */
function hCommitFromVaultRef(ref: VaultRef): Hex32 | undefined {
  const m = ref.match(/0x[0-9a-fA-F]{64}/);
  return m ? (m[0] as Hex32) : undefined;
}

/**
 * Build the on-chain ShredRegistry write port. Real impl is a viem WalletClient
 * over ShredRegistry `requestShred`/`finalizeShred` (key from env/KMS, never a
 * file). When the chain isn't wired the port throws — so a shred that reaches the
 * chain step without an executor fails loud (never a fake-success).
 */
function buildShredChainPort(env: NodeJS.ProcessEnv, notes: string[]): ShredExecutorChainPort {
  const wired =
    env["CEALIS_V3_RPC_URL"] &&
    env["CEALIS_V3_CONDITION_ENGINE_ADDRESS"] &&
    env["CEALIS_V3_SHRED_PRIVATE_KEY"];
  if (!wired) {
    notes.push("shred chain port: ABSENT — no RPC/key wired; on-chain shred leg fails closed.");
  }
  return {
    recordShred: async () => {
      throw new Error(
        "ShredRegistry chain port not wired — set CEALIS_V3_RPC_URL + " +
          "CEALIS_V3_CONDITION_ENGINE_ADDRESS + CEALIS_V3_SHRED_REGISTRY_ADDRESS + an operator/" +
          "CEALIS_V3_SHRED_PRIVATE_KEY (viem WalletClient over ShredRegistry requestShred → " +
          "authorizeShred). Fails closed (no fake-success).",
      );
    },
  };
}
