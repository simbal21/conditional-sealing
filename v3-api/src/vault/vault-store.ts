// VaultStore — the atomic per-blob storage seam beneath CealisV3VaultImpl.
//
// Why a store seam (not just `VaultBackend`): the frozen `VaultBackend`
// (cealis-v3-vault.ts) is a PURE raw-byte seam (key→bytes) with no binding /
// metadata / retention semantics. But C1 inseparability + idempotent-put
// collision detection + the append-only shred-audit write all require the
// ciphertext, its commit binding, and its metadata to live and move as ONE
// atomic unit. `VaultStore` is that unit; CealisV3VaultImpl is backend-agnostic
// because it talks ONLY to `VaultStore`. Concrete stores:
//   - PostgresVaultStore  → one `vault_blobs` row, written atomically; shred row
//                            appended to the append-only `vault_audit_log`.
//   - FilesystemVaultStore → bytes file + metadata sidecar; shred audit appended
//                            to an append-only JSONL log.
// Both compose the raw byte seam where natural (PostgresVaultStore wraps a
// `PostgresBlobBackend`; FilesystemVaultStore wraps a `FilesystemBackend`).
//
// GDPR / C1 discipline lives in the impls; this file is the contract only.

import type {
  ShredAuthority,
  VaultBackendId,
  VaultBlob,
  VaultBlobMeta,
  VaultCommitBinding,
  VaultRef,
} from "./cealis-v3-vault.js";

/** A complete, atomic blob record: opaque ciphertext + inseparable binding +
 *  non-secret metadata. Persisted and retrieved as one unit (C1). */
export interface VaultStoreRecord {
  readonly ref: VaultRef;
  readonly ciphertext: Uint8Array;
  readonly commitBinding: VaultCommitBinding;
  readonly meta: VaultBlobMeta;
}

/** Result of an idempotent put attempt at the store layer. `collision` is true
 *  iff the ref already exists with DIFFERENT ciphertext-or-binding bytes (the
 *  vault layer maps this to VAULT_REF_COLLISION). */
export interface VaultStorePutResult {
  readonly stored: boolean;
  readonly collision: boolean;
}

/** Append-only shred-audit row written on every successful `deleteRecord`. */
export interface VaultShredAuditRow {
  readonly ref: VaultRef;
  readonly shredAuthority: ShredAuthority;
  readonly shreddedAt: string;
}

export interface VaultStore {
  readonly backendId: VaultBackendId;

  /** Atomically persist a full record. Idempotent on `ref`: identical bytes →
   *  `{stored:false, collision:false}`; different bytes → `{stored:false,
   *  collision:true}`; new ref → `{stored:true, collision:false}`. */
  putRecord(record: VaultStoreRecord): Promise<VaultStorePutResult>;

  /** Retrieve the full inseparable record, or `undefined` if absent/shredded. */
  getRecord(ref: VaultRef): Promise<VaultBlob | undefined>;

  /** Delete the ciphertext + binding + metadata AND append a shred-audit row in
   *  the same logical operation. Returns `false` if the ref did not exist. */
  deleteRecord(audit: VaultShredAuditRow): Promise<boolean>;

  /** Metadata-only read for retention status (no ciphertext load). */
  getMeta(ref: VaultRef): Promise<VaultBlobMeta | undefined>;

  /** Refs whose `retention_expires_at <= asOf` (for the retention worker). */
  listExpired(asOf: string): Promise<readonly VaultRef[]>;
}
