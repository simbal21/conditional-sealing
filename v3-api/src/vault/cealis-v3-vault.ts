// CealisV3Vault — FROZEN PRODUCER SEAM (R2a task #2, interface-only, NO impl).
//
// This is the opaque-ciphertext blob store. It is one of TWO distinct seams (do not
// conflate): (a) THIS — opaque encrypted-blob storage keyed by an opaque vault ref;
// (b) RevealArtifactRepository (../bundle/persist.ts:39) — the SEPARATE metadata /
// status / manifest / bundle-record store, frozen as-is by task #3. CealisV3Vault
// never touches metadata and never sees plaintext or key material.
//
// Construction discipline (binding, mirrors the C3a per-step-reader discipline):
//   - OPAQUE BYTES ONLY. No `dek`, no key, no `plaintext` parameter appears anywhere
//     in this interface. Sealing (encryptPayload / the TEE boundary) happens UPSTREAM;
//     the vault stores already-encrypted bytes and can never decrypt.
//   - C1 inseparability: a stored blob ALWAYS travels with its `VaultCommitBinding`.
//     `getBlob` returns ciphertext and binding as ONE inseparable record — there is no
//     accessor that yields ciphertext without the commit binding. This makes
//     "consume ciphertext without its commit binding" unrepresentable at the type
//     boundary, so the combiner's commitAAD round-trip (C1) can be made UNCONDITIONAL
//     (the vault does not verify — not its job — it guarantees the binding cannot be
//     lost or separated, which is the type-level enabler for C1's unconditional check).
//   - Backend swappable (Rule 12 production-grade): `VaultBackend` is the storage seam
//     (PostgresBlob + Filesystem now; S3/R2/IPFS later). Real backends only — no
//     dev-shortcut/in-memory backend ships.
//
// Isolation (SECURITY.md): no @cealis/shared, no ../../packages/* (V1),
// no V1 role names / TAGs. Storage backend uses the V3 DB (cealis_v3_dev) only.
// Retention: ciphertext = obligation duration + 3y (§195 BGB) — see legal-constraints.md.

import type { RetentionStatus } from "./retention-status.js";

/**
 * Opaque vault reference. Caller-supplied; scheme is the caller's concern
 * (`vault://reveal-artifacts/{authId}/{urlencoded recipientRef}` for reveal bundles
 * per ../bundle/persist.ts:107 `bundleStorageRef`; an analogous deterministic
 * `vault://{h_commit}`-class key for ingestion ciphertext). The vault treats it as
 * an opaque, collision-free key and never parses it for semantics.
 */
export type VaultRef = string;

/**
 * Inseparable commit binding stored alongside every blob and ALWAYS returned with it.
 * Carries exactly the on-wire bytes the combiner needs to perform an UNCONDITIONAL
 * commitAAD round-trip (closes C1 by construction at the consumer): the raw on-wire
 * `commit_version` (NOT a post-decode/patched struct field) and the commitAAD digest
 * the round-trip is checked against. The vault does not interpret these.
 */
export interface VaultCommitBinding {
  /** FULL raw on-wire commit_AAD bytes, exactly as committed. This is the input the
   *  combiner's `verifyCommitAADRoundTrip` re-encodes and BYTE-compares against
   *  (v3-custody pre-verify-pipeline.ts:113 `bytesEqual(encoded, commitAADBytes)`).
   *  Carrying the BYTES (not merely a digest) is what makes the round-trip
   *  performable UNCONDITIONALLY — a digest alone cannot be re-encode-compared, which
   *  would force the combiner to re-derive elsewhere and reopen C1. Inseparable from
   *  the ciphertext (returned only inside VaultBlob). */
  readonly commit_aad_bytes: Uint8Array;
  /** Raw on-wire commit_version, read from `commit_aad_bytes` at the canonical
   *  COMMIT_VERSION_OFFSET (numeric, per profile-dispatch.ts:52-56) — NEVER the
   *  post-decode value. `decodeActiveCompatibleCommitAAD` patches historical
   *  versions up to ACTIVE; using the patched value in the round-trip conditional is
   *  the confirmed C1 defeat (pre-verify-pipeline.ts:55). The combiner's unconditional
   *  round-trip MUST gate on THIS value, not the decoded struct field. */
  readonly commit_version_onwire: number;
  /** On-chain commitment digest the re-encoded commit_AAD is ultimately bound
   *  against (the anchor the round-trip result is checked to match). */
  readonly commit_aad_digest: string;
}

/** PDA-configured shred authority (legal-constraints.md `shredding_authority`). */
export type ShredAuthority = "subject" | "joint" | "operator" | "timelock" | "disabled";

/** Opaque blob + its inseparable commit binding. The ONLY shape `getBlob` yields —
 *  no ciphertext-without-binding accessor exists (C1 type-level enabler). */
export interface VaultBlob {
  readonly ciphertext: Uint8Array;
  readonly commitBinding: VaultCommitBinding;
  readonly meta: VaultBlobMeta;
}

/** Non-secret metadata stored with the blob. Contains NO key/DEK/plaintext. */
export interface VaultBlobMeta {
  readonly payload_classification: Record<string, unknown>;
  readonly retention_policy_id: string;
  readonly retention_expires_at: string;
  readonly byte_len: number;
  readonly created_at: string;
}

/** Identifies the concrete storage backend a ref is bound to (for error context +
 *  multi-backend routing). */
export type VaultBackendId = "postgres-blob" | "filesystem" | "s3" | "r2" | "ipfs";

/** Rule-47 pre-declared error-context surface. Every CealisV3Vault failure carries
 *  this bag so the caller can act without a debugger/recompile. */
export interface VaultErrorContext {
  readonly vaultRef?: VaultRef;
  readonly vaultBackendId?: VaultBackendId;
  readonly retentionPolicyId?: string;
  readonly retentionExpiresAt?: string;
  readonly blobByteLen?: number;
  readonly shredAuthority?: ShredAuthority;
  /** Raw on-wire commit_version of the blob's binding (C1 diagnostics). */
  readonly commitVersion?: number;
  /** Whether the inseparable commit binding was present + well-formed for the
   *  downstream unconditional round-trip ("present" | "missing" | "malformed"). */
  readonly commitAADRoundTripStatus?: "present" | "missing" | "malformed";
  readonly operation?: "putBlob" | "getBlob" | "deleteBlob" | "getRetentionStatus" | "listExpired";
  readonly reasonCode?: VaultErrorReason;
}

export type VaultErrorReason =
  | "VAULT_REF_NOT_FOUND"
  | "VAULT_REF_COLLISION"
  | "VAULT_COMMIT_BINDING_MISSING"
  | "VAULT_BACKEND_UNAVAILABLE"
  | "VAULT_SHRED_AUTHORITY_DISABLED"
  | "VAULT_SHRED_AUTHORITY_DENIED"
  | "VAULT_RETENTION_NOT_EXPIRED"
  | "VAULT_BLOB_INTEGRITY_FAIL";

export class VaultError extends Error {
  readonly context: VaultErrorContext;
  constructor(message: string, context: VaultErrorContext) {
    super(message);
    this.name = "VaultError";
    this.context = context;
  }
}

/**
 * The opaque-ciphertext vault. Implementations (R2b) wrap a `VaultBackend`.
 * Every method is async and fail-closed (throws `VaultError` with context).
 */
export interface CealisV3Vault {
  /**
   * Store an opaque ciphertext blob with its inseparable commit binding.
   * `ciphertext` is already-encrypted bytes — the vault cannot decrypt and is never
   * given a key. Idempotent on `ref` (same ref + same bytes = no-op; same ref +
   * different bytes = `VAULT_REF_COLLISION`).
   */
  putBlob(input: {
    readonly ref: VaultRef;
    readonly ciphertext: Uint8Array;
    readonly commitBinding: VaultCommitBinding;
    readonly meta: Omit<VaultBlobMeta, "byte_len" | "created_at">;
  }): Promise<{ readonly ref: VaultRef; readonly byte_len: number }>;

  /** Retrieve ciphertext AND its commit binding as one inseparable record.
   *  No variant returns ciphertext alone (C1 construction). */
  getBlob(ref: VaultRef): Promise<VaultBlob>;

  /**
   * Crypto-shred: delete the opaque blob (vault's part of right-to-erasure).
   * DEK destruction is M1/M3's responsibility, NOT the vault's — this only removes
   * the stored ciphertext + binding and writes an append-only shred audit row.
   * `shredAuthority` is required and authority-checked: `"disabled"` MUST throw
   * `VAULT_SHRED_AUTHORITY_DISABLED` (some use cases deliberately disable erasure).
   */
  deleteBlob(input: {
    readonly ref: VaultRef;
    readonly shredAuthority: ShredAuthority;
  }): Promise<{ readonly ref: VaultRef; readonly shredded_at: string }>;

  /** Retention status for a stored ref. Returns the canonical RetentionStatus
   *  (reused from ./retention-status.js — not redefined). */
  getRetentionStatus(ref: VaultRef): Promise<RetentionStatus>;

  /** Refs whose retention has expired as of `asOf` (for the retention worker, H8).
   *  Returns refs only — the worker decides shred per policy. */
  listExpired(asOf: string): Promise<readonly VaultRef[]>;
}

/**
 * Swappable storage backend seam (Rule 12). Pure opaque byte storage keyed by ref —
 * no commit-binding/retention/shred-authority semantics (those live in the
 * CealisV3Vault layer above). R2b ships PostgresBlobBackend (cealis_v3_dev `bytea`)
 * and FilesystemBackend; S3/R2/IPFS later, selected per-PDA/per-env. No in-memory
 * backend ships (dev-shortcut = Rule 12 violation).
 */
export interface VaultBackend {
  readonly backendId: VaultBackendId;
  put(key: string, bytes: Uint8Array): Promise<void>;
  get(key: string): Promise<Uint8Array | undefined>;
  delete(key: string): Promise<void>;
  listKeys(prefix?: string): Promise<readonly string[]>;
}
