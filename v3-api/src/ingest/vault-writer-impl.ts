// RealVaultWriter (T1.2 + F-WRAP-1) — the real ingest-time seal → deal → WRAP →
// store → destroy path. Replaces `SyntheticVaultWriter` (routes-create-mode-a.ts).
//
// FLOW (the §6.2 wrap-to-gate landing in the ingest path):
//   1. SEAL   — the injected `SealerPort` (the Phase-1↔Phase-2 TEE boundary;
//               the in-process stub is `g4/sealed-code-server.ts
//               sealPlaintextForVault`, NODE_ENV=production-guarded) generates a
//               commit-time DEK and AEAD-encrypts the plaintext under it, plus
//               the inseparable commit-AAD binding (C1). It surfaces the inner
//               AEAD payload ciphertext + commit_context_digest_0.
//   2. DEAL   — `dealDek(dek, profile)` (@cealis/v3-crypto) Shamir-splits the DEK
//               into distinct, information-theoretically-independent ShareRecords
//               for the PDA-selected `AccessStructureProfile`. NOTHING hardcoded:
//               the profile comes from the PDA `conditional_recipients_policy`
//               via the injected context resolver (platform principle).
//   3. WRAP   — `wrapDealtShares` (S2-1 §6.2.3) hybrid-PQ-wraps EACH dealt share
//               to ITS gate's recipient pubkey (RFC 9180 HPKE: ML-KEM-768 +
//               X25519). The per-gate recipient pubkeys come from the injected
//               `GateRecipientKeyProvider` (production: GateRecipientPubkeyRegistry;
//               local E2E: per-commit-generated + registered). It assembles the
//               canonical age envelope (wrapped stanzas + payload ciphertext).
//               *** THE NON-CUSTODY INVARIANT LANDS HERE: after this step the only
//               share-bearing material is WRAPPED — a single gate's privkey
//               unwraps at most ITS share (Shamir: one share is zero info on the
//               DEK), and the server holding the whole DB but no gate privkey
//               cannot reconstruct anything. ***
//   4. STORE  — `vault.putBlob(ageEnvelope, binding)` persists the opaque age
//               envelope + its inseparable `VaultCommitBinding`; the per-stanza
//               WRAPPED routing records are persisted to the `dek_share_records`
//               seam via the injected `ShareRecordStore` — NEVER a raw share.
//   5. DESTROY — the DEK and every raw share value are zeroized from process
//               memory immediately after persistence (crypto-shred discipline:
//               the only key material that survives is the WRAPPED, threshold-
//               protected, persisted stanzas — never the assembled DEK, never an
//               unwrapped share).
//
// Why a context resolver instead of widening `VaultWriter.write`: the merged
// `VaultWriter` interface (routes-create-mode-a.ts) is a frozen wiring seam
// (`write({ h_commit, plaintext, payload_classification }) → { vault_ref }`) and
// is a Wave-5 file. The per-ingest context the real writer needs — the
// `HCommitArtifacts` (commit_AAD bytes + commit_context_digest the sealer binds),
// the PDA-selected `AccessStructureProfile`, the `shred_authority`, and the
// retention floor — all come from the PDA, not from the narrow write() call. The
// composition root (Wave 5) provides an `IngestContextResolver` that maps the
// in-flight `h_commit` to that context (it already computed `HCommitArtifacts`
// before calling `write`). This keeps the call shape untouched while threading
// PDA config into the runtime.
//
// GDPR / legal (internal legal-constraints rules):
//   - No PII at rest except the vault ciphertext (AEAD under the DEK). The
//     plaintext passed to `write` is sealed and never persisted in cleartext.
//   - The vault never receives the DEK (CealisV3Vault has no key parameter); the
//     DEK exists only transiently in this writer and the sealer, and is zeroized.
//   - Share records ARE key material and are destroyed on shred (T4.2); here they
//     are persisted WRAPPED (§6.2 hybrid-wrap payload) only — never a standalone
//     reconstructing plaintext share.
//   - `retention_expires_at` is populated at ingest with the PDA's retention floor.
//
// V3 isolation (SECURITY.md): no @cealis/shared, no V1 packages, no
// V1 env vars (the sealed-share / issuer-salt / committee-key family — see
// SECURITY.md). The crypto comes from @cealis/v3-crypto via the m1 facade.

import { dealDek, type AccessStructureProfile, type ShareRecord } from "../m1-imports.js";
import type { Hex32 } from "../h-commit/index.js";
import type { HCommitArtifacts } from "../h-commit/construct.js";
import type {
  CealisV3Vault,
  ShredAuthority,
  VaultCommitBinding,
} from "../vault/cealis-v3-vault.js";
import type { VaultWriter } from "./routes-create-mode-a.js";
import {
  wrapDealtShares,
  type G3Choice,
  type GateRecipientPubkeyMap,
  type WrappedShareRecord,
} from "./wrap-shares.js";

/**
 * Output of the sealing step (the TEE boundary). Unlike the in-process stub
 * `sealPlaintextForVault` — which zeroizes its DEK before returning and so only
 * yields ciphertext — the writer's `SealerPort` MUST surface the commit-time DEK
 * so the dealer can split it. The DEK is transient: the writer zeroizes it the
 * instant the deal completes.
 *
 * `commit_aad_bytes` / `commit_version_onwire` / `commit_aad_digest` are exactly
 * the inseparable `VaultCommitBinding` fields the combiner re-encodes for the
 * unconditional C1 round-trip at reveal time.
 */
export interface SealOutput {
  /** Commit-time DEK (32 bytes). TRANSIENT — the writer zeroizes it after deal. */
  readonly dek: Uint8Array;
  /**
   * Inner AEAD payload ciphertext under the DEK. The writer wraps the dealt
   * shares into per-gate stanzas and places THIS at the tail of the canonical
   * age envelope — the enveloped bytes are what the vault stores and the
   * combiner's `decryptAeadPayload` consumes. The only PII-bearing artifact at
   * rest (and only behind the DEK + commit-AAD binding).
   */
  readonly ciphertext: Uint8Array;
  /** `commit_context_digest_0` (32 bytes) — the AEAD's per-payload nonce/AAD
   *  binding the combiner needs at reveal (carried into σ metadata). */
  readonly commit_context_digest_0: Uint8Array;
  /** Full raw on-wire commit_AAD bytes (C1 inseparable binding input). */
  readonly commit_aad_bytes: Uint8Array;
  /** Raw on-wire commit_version (NOT a post-decode/patched value). */
  readonly commit_version_onwire: number;
  /** Commit-AAD digest the round-trip is ultimately checked against. */
  readonly commit_aad_digest: string;
  /** 32-byte plugin_version_digest (the §6.2 wrap AAD binds it per stanza). */
  readonly plugin_version_digest: Uint8Array;
  /** 32-byte commit_context_digest_N (the §6.2 wrap AAD binds it per stanza). */
  readonly commit_context_digest_N: Uint8Array;
}

/**
 * The seal-the-plaintext boundary. The real implementation is a Nitro Enclave /
 * cloud HSM-TEE call (vendor-gated, external gate §5); the Phase-3 in-process
 * stub wraps `g4/sealed-code-server.ts sealPlaintextForVault` (which is
 * NODE_ENV=production-guarded so it fails loud if mistakenly used in prod). The
 * sealer is injected at the composition root — this writer never reaches into a
 * concrete TEE.
 */
export interface SealerPort {
  seal(input: {
    readonly hCommit: HCommitArtifacts;
    readonly plaintext: Uint8Array;
  }): Promise<SealOutput> | SealOutput;
}

/**
 * Persistence seam for the WRAPPED DEK share stanzas — the `dek_share_records`
 * table (migration 0006). Injected so this writer stays decoupled from the DB
 * wiring (T0.1/T1.1) and is unit-testable with a fake. The records arrive as
 * `WrappedShareRecord`s carrying the §6.2 hybrid-wrap payload (NEVER a raw share
 * value); the store persists the routing metadata + the opaque wrapped payload.
 *
 * NON-CUSTODY INVARIANT: `dek_share_records` MUST hold only WRAPPED material —
 * a row's `wrapped_payload` is decryptable only by ITS gate's private key, and a
 * single gate's share is information-theoretically zero on the DEK (Shamir).
 */
export interface ShareRecordStore {
  persist(input: {
    readonly h_commit: Hex32;
    readonly records: readonly WrappedShareRecord[];
  }): Promise<void>;
}

/**
 * Resolver for the per-gate recipient KEM public keys each dealt share is wrapped
 * to at commit time. Keyed by `${gateKind}:${conditionalRecipientIndex}`.
 *
 * PRODUCTION: reads `GateRecipientPubkeyRegistry` (per-commit ephemeral for
 * Lit/G4/Conditional; long-lived committee for drand) at the commit block per
 * S2-3 gate-recipient-pubkey lifecycle. The corresponding PRIVATE keys live only
 * inside each gate's TEE/threshold network — never server-side.
 *
 * LOCAL E2E: the composition root generates a per-commit gate keypair set,
 * registers the PUBLIC keys here, and hands the PRIVATE keys to the local stub
 * gate clients (which stand in for the real Lit/G3/G4/Conditional TEEs).
 */
export interface GateRecipientKeyProvider {
  resolve(input: {
    readonly h_commit: Hex32;
    readonly profile: AccessStructureProfile;
    readonly g3Choice: G3Choice;
  }): Promise<GateRecipientPubkeyMap> | GateRecipientPubkeyMap;
}

/**
 * Per-ingest context the real writer needs but the narrow `VaultWriter.write`
 * call does not carry. The composition root resolves it from the PDA + the
 * already-computed `HCommitArtifacts` for the in-flight commit. NOTHING here is
 * hardcoded — `accessStructureProfile`, `shredAuthority`, `retentionPolicyId`,
 * and `retentionExpiresAt` are PDA-derived (platform principle).
 */
export interface IngestWriteContext {
  /** The full commit artifacts (commit_AAD + commit_context_digest) the sealer binds. */
  readonly hCommit: HCommitArtifacts;
  /** PDA-selected access structure — from `conditional_recipients_policy`. */
  readonly accessStructureProfile: AccessStructureProfile;
  /** PDA-configured retention policy id (e.g. `obligation_plus_3y`). */
  readonly retentionPolicyId: string;
  /** ISO retention expiry, populated at ingest from the PDA retention floor. */
  readonly retentionExpiresAt: string;
  /** PDA-configured shred authority (carried into the vault put for context;
   *  the actual erasure happens at shred time per this authority). */
  readonly shredAuthority: ShredAuthority;
  /** Opaque vault ref to store under. Caller-supplied scheme (the vault treats
   *  it as an opaque, collision-free key). */
  readonly vaultRef: string;
}

/**
 * Resolve the per-ingest context for an in-flight write. Keyed by the same
 * `h_commit` the route passes to `write`. The composition root implements this
 * against the PDA + the artifacts it computed pre-write.
 */
export interface IngestContextResolver {
  resolve(input: {
    readonly h_commit: Hex32;
    readonly payload_classification: Record<string, unknown>;
  }): Promise<IngestWriteContext> | IngestWriteContext;
}

export interface RealVaultWriterOptions {
  readonly sealer: SealerPort;
  readonly vault: CealisV3Vault;
  readonly shareStore: ShareRecordStore;
  readonly resolveContext: IngestContextResolver;
  /** Resolves the per-gate recipient KEM pubkeys each dealt share is wrapped to
   *  (§6.2). MANDATORY — without it the writer cannot wrap and refuses to persist
   *  (it must NEVER fall back to storing a raw share). */
  readonly gateRecipientKeys: GateRecipientKeyProvider;
  /** Test-only override of the dealer (deterministic coefficients). Production
   *  omits it — `dealDek` then uses the platform CSPRNG. */
  readonly dealDekFn?: typeof dealDek;
}

/** Zero a buffer in place (best-effort crypto-shred of transient key material). */
function zeroize(buffer: Uint8Array | undefined): void {
  if (buffer instanceof Uint8Array) buffer.fill(0);
}

/**
 * The real `VaultWriter`. Implements the existing narrow interface so the
 * composition root can inject it exactly where `SyntheticVaultWriter` sits today.
 */
export class RealVaultWriter implements VaultWriter {
  private readonly sealer: SealerPort;
  private readonly vault: CealisV3Vault;
  private readonly shareStore: ShareRecordStore;
  private readonly resolveContext: IngestContextResolver;
  private readonly gateRecipientKeys: GateRecipientKeyProvider;
  private readonly dealDekFn: typeof dealDek;

  constructor(options: RealVaultWriterOptions) {
    this.sealer = options.sealer;
    this.vault = options.vault;
    this.shareStore = options.shareStore;
    this.resolveContext = options.resolveContext;
    this.gateRecipientKeys = options.gateRecipientKeys;
    this.dealDekFn = options.dealDekFn ?? dealDek;
  }

  async write(input: {
    readonly h_commit: Hex32;
    readonly plaintext: Uint8Array;
    readonly payload_classification: Record<string, unknown>;
  }): Promise<{ readonly vault_ref: string }> {
    const context = await this.resolveContext.resolve({
      h_commit: input.h_commit,
      payload_classification: input.payload_classification,
    });

    const g3Choice: G3Choice = context.hCommit.commit_AAD.g3_choice === 0 ? "dcipher" : "drand";

    // Resolve the per-gate recipient KEM pubkeys BEFORE sealing so a missing key
    // fails closed before any DEK exists (the writer must never deal a DEK it
    // cannot fully wrap, which would force a raw-share fallback).
    const recipients = await this.gateRecipientKeys.resolve({
      h_commit: input.h_commit,
      profile: context.accessStructureProfile,
      g3Choice,
    });

    // 1. SEAL — the TEE boundary generates the DEK + inner AEAD ciphertext +
    //    commit binding + the per-payload commit_context_digest_0.
    const sealed = await this.sealer.seal({
      hCommit: context.hCommit,
      plaintext: input.plaintext,
    });

    // Hold the dealt records at method scope so the `finally` can zeroize their
    // raw values on every exit path (including a failure between deal and store).
    let records: ShareRecord[] | undefined;
    try {
      // 2. DEAL — Shamir-split the DEK into the PDA-selected access structure.
      const dealt: ShareRecord[] = this.dealDekFn(sealed.dek, context.accessStructureProfile);
      records = dealt;

      // 3. WRAP — hybrid-PQ-wrap EACH share to ITS gate's recipient pubkey
      //    (§6.2) and assemble the canonical age envelope. After this line the
      //    only share-bearing material in scope is WRAPPED. *** non-custody ***
      const { ageEnvelope, wrappedRecords } = wrapDealtShares({
        records: dealt,
        recipients,
        pluginVersionDigest: sealed.plugin_version_digest,
        commitContextDigestN: sealed.commit_context_digest_N,
        commitContextDigest0: sealed.commit_context_digest_0,
        g3Choice,
        payloadCiphertext: sealed.ciphertext,
      });

      // 4a. STORE the age envelope (wrapped stanzas + payload) + inseparable
      //     commit binding (C1) in the vault. The vault never sees a raw share.
      const commitBinding: VaultCommitBinding = {
        commit_aad_bytes: sealed.commit_aad_bytes,
        commit_version_onwire: sealed.commit_version_onwire,
        commit_aad_digest: sealed.commit_aad_digest,
      };
      await this.vault.putBlob({
        ref: context.vaultRef,
        ciphertext: ageEnvelope,
        commitBinding,
        meta: {
          payload_classification: input.payload_classification,
          retention_policy_id: context.retentionPolicyId,
          retention_expires_at: context.retentionExpiresAt,
        },
      });

      // 4b. STORE the WRAPPED per-stanza routing records in dek_share_records.
      //     NEVER a raw 32-byte share — only the §6.2 wrapped payload.
      await this.shareStore.persist({ h_commit: input.h_commit, records: wrappedRecords });

      return { vault_ref: context.vaultRef };
    } finally {
      // 5. DESTROY — zeroize the assembled DEK and every RAW share value from
      //    process memory the instant persistence is done (or has failed). The
      //    only key material that survives is the WRAPPED, threshold-protected,
      //    persisted stanzas; the reconstructable DEK and any unwrapped share
      //    must never linger.
      zeroize(sealed.dek);
      if (records !== undefined) {
        for (const record of records) zeroize(record.value);
      }
    }
  }
}

/** Factory mirroring the merged idiom (createProductionSigmaGatherer-style). */
export function createRealVaultWriter(options: RealVaultWriterOptions): RealVaultWriter {
  return new RealVaultWriter(options);
}
