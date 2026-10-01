// CealisV3VaultImpl — the real impl of the frozen `CealisV3Vault` producer seam
// (cealis-v3-vault.ts). Backend-agnostic: it talks ONLY to a `VaultStore`
// (PostgresVaultStore or FilesystemVaultStore today; S3/R2/IPFS later behind the
// same seam). The vault stores already-encrypted bytes, never sees plaintext or
// the DEK, and never decrypts.
//
// What this layer owns (mapping the store to the interface contract):
//   - putBlob   : compute byte_len + created_at, drive the store's idempotent
//                 put, map a different-bytes-same-ref to VAULT_REF_COLLISION.
//   - getBlob   : return ciphertext + inseparable binding as ONE record (C1);
//                 a missing ref → VAULT_REF_NOT_FOUND; a record missing its
//                 binding → VAULT_COMMIT_BINDING_MISSING (defends the C1 enabler).
//   - deleteBlob: crypto-shred. `shredAuthority === "disabled"` → throw
//                 VAULT_SHRED_AUTHORITY_DISABLED (erasure intentionally off for
//                 testament/archival/evidence). Otherwise delete + append-only
//                 shred-audit row, irreversibly (a subsequent getBlob → NOT_FOUND).
//   - getRetentionStatus / listExpired : retention-worker surface (metadata only).
//
// Every failure throws `VaultError` with the Rule-47 pre-declared context bag.
//
// V3 isolation (SECURITY.md): no @cealis/shared, no V1 packages, no
// V1 env vars. The concrete store + its DB/FS client are injected at the
// composition root.

import {
  VaultError,
  type CealisV3Vault,
  type ShredAuthority,
  type VaultBackendId,
  type VaultBlob,
  type VaultBlobMeta,
  type VaultCommitBinding,
  type VaultRef,
} from "./cealis-v3-vault.js";
import { buildRetentionStatus, type RetentionStatus } from "./retention-status.js";
import type { VaultStore } from "./vault-store.js";

export interface CealisV3VaultImplOptions {
  /** The atomic per-blob store (binding + metadata + bytes + shred-audit). */
  readonly store: VaultStore;
  /** Wall-clock source (injectable for deterministic tests). */
  readonly now?: () => Date;
}

/** A commit binding is well-formed iff it carries non-empty on-wire bytes, a
 *  numeric version, and a digest. Empty/absent bytes defeat the unconditional
 *  C1 round-trip, so the vault refuses to store/return such a record. */
function bindingStatus(
  binding: VaultCommitBinding | undefined,
): "present" | "missing" | "malformed" {
  if (!binding) return "missing";
  if (
    !(binding.commit_aad_bytes instanceof Uint8Array) ||
    binding.commit_aad_bytes.byteLength === 0 ||
    typeof binding.commit_version_onwire !== "number" ||
    typeof binding.commit_aad_digest !== "string" ||
    binding.commit_aad_digest.length === 0
  ) {
    return "malformed";
  }
  return "present";
}

export class CealisV3VaultImpl implements CealisV3Vault {
  private readonly store: VaultStore;
  private readonly now: () => Date;
  private readonly backendId: VaultBackendId;

  constructor(options: CealisV3VaultImplOptions) {
    this.store = options.store;
    this.now = options.now ?? (() => new Date());
    this.backendId = options.store.backendId;
  }

  async putBlob(input: {
    readonly ref: VaultRef;
    readonly ciphertext: Uint8Array;
    readonly commitBinding: VaultCommitBinding;
    readonly meta: Omit<VaultBlobMeta, "byte_len" | "created_at">;
  }): Promise<{ readonly ref: VaultRef; readonly byte_len: number }> {
    const status = bindingStatus(input.commitBinding);
    if (status !== "present") {
      throw new VaultError("commit binding missing or malformed at putBlob", {
        vaultRef: input.ref,
        vaultBackendId: this.backendId,
        commitAADRoundTripStatus: status,
        operation: "putBlob",
        reasonCode: "VAULT_COMMIT_BINDING_MISSING",
      });
    }
    if (!(input.ciphertext instanceof Uint8Array)) {
      // Never accept anything but opaque bytes — the vault stores ciphertext only.
      throw new VaultError("ciphertext must be opaque bytes at putBlob", {
        vaultRef: input.ref,
        vaultBackendId: this.backendId,
        operation: "putBlob",
        reasonCode: "VAULT_BLOB_INTEGRITY_FAIL",
      });
    }

    const byteLen = input.ciphertext.byteLength;
    const createdAt = this.now().toISOString();
    const fullMeta: VaultBlobMeta = {
      payload_classification: input.meta.payload_classification,
      retention_policy_id: input.meta.retention_policy_id,
      retention_expires_at: input.meta.retention_expires_at,
      byte_len: byteLen,
      created_at: createdAt,
    };

    let result;
    try {
      result = await this.store.putRecord({
        ref: input.ref,
        ciphertext: input.ciphertext,
        commitBinding: input.commitBinding,
        meta: fullMeta,
      });
    } catch {
      throw new VaultError("vault backend unavailable at putBlob", {
        vaultRef: input.ref,
        vaultBackendId: this.backendId,
        retentionPolicyId: input.meta.retention_policy_id,
        retentionExpiresAt: input.meta.retention_expires_at,
        blobByteLen: byteLen,
        commitVersion: input.commitBinding.commit_version_onwire,
        commitAADRoundTripStatus: "present",
        operation: "putBlob",
        reasonCode: "VAULT_BACKEND_UNAVAILABLE",
      });
    }

    if (result.collision) {
      throw new VaultError("ref already stored with different bytes (collision)", {
        vaultRef: input.ref,
        vaultBackendId: this.backendId,
        blobByteLen: byteLen,
        commitVersion: input.commitBinding.commit_version_onwire,
        operation: "putBlob",
        reasonCode: "VAULT_REF_COLLISION",
      });
    }

    // stored OR idempotent no-op (same bytes) → return the byte_len.
    return { ref: input.ref, byte_len: byteLen };
  }

  async getBlob(ref: VaultRef): Promise<VaultBlob> {
    let record: VaultBlob | undefined;
    try {
      record = await this.store.getRecord(ref);
    } catch {
      throw new VaultError("vault backend unavailable at getBlob", {
        vaultRef: ref,
        vaultBackendId: this.backendId,
        operation: "getBlob",
        reasonCode: "VAULT_BACKEND_UNAVAILABLE",
      });
    }
    if (!record) {
      throw new VaultError("vault ref not found at getBlob", {
        vaultRef: ref,
        vaultBackendId: this.backendId,
        operation: "getBlob",
        reasonCode: "VAULT_REF_NOT_FOUND",
      });
    }
    // Defend the C1 type-level enabler at runtime: never hand back ciphertext
    // whose inseparable binding is missing/malformed.
    const status = bindingStatus(record.commitBinding);
    if (status !== "present") {
      throw new VaultError("commit binding missing or malformed at getBlob", {
        vaultRef: ref,
        vaultBackendId: this.backendId,
        commitAADRoundTripStatus: status,
        operation: "getBlob",
        reasonCode: "VAULT_COMMIT_BINDING_MISSING",
      });
    }
    return record;
  }

  async deleteBlob(input: {
    readonly ref: VaultRef;
    readonly shredAuthority: ShredAuthority;
  }): Promise<{ readonly ref: VaultRef; readonly shredded_at: string }> {
    if (input.shredAuthority === "disabled") {
      // Erasure deliberately disabled for this use case (testament / archival /
      // evidence provenance). Absence of an erasure path is a FEATURE here.
      throw new VaultError("shred authority disabled — erasure not permitted", {
        vaultRef: input.ref,
        vaultBackendId: this.backendId,
        shredAuthority: input.shredAuthority,
        operation: "deleteBlob",
        reasonCode: "VAULT_SHRED_AUTHORITY_DISABLED",
      });
    }

    const shreddedAt = this.now().toISOString();
    let deleted: boolean;
    try {
      deleted = await this.store.deleteRecord({
        ref: input.ref,
        shredAuthority: input.shredAuthority,
        shreddedAt,
      });
    } catch {
      throw new VaultError("vault backend unavailable at deleteBlob", {
        vaultRef: input.ref,
        vaultBackendId: this.backendId,
        shredAuthority: input.shredAuthority,
        operation: "deleteBlob",
        reasonCode: "VAULT_BACKEND_UNAVAILABLE",
      });
    }
    if (!deleted) {
      throw new VaultError("vault ref not found at deleteBlob", {
        vaultRef: input.ref,
        vaultBackendId: this.backendId,
        shredAuthority: input.shredAuthority,
        operation: "deleteBlob",
        reasonCode: "VAULT_REF_NOT_FOUND",
      });
    }
    return { ref: input.ref, shredded_at: shreddedAt };
  }

  async getRetentionStatus(ref: VaultRef): Promise<RetentionStatus> {
    let meta: VaultBlobMeta | undefined;
    try {
      meta = await this.store.getMeta(ref);
    } catch {
      throw new VaultError("vault backend unavailable at getRetentionStatus", {
        vaultRef: ref,
        vaultBackendId: this.backendId,
        operation: "getRetentionStatus",
        reasonCode: "VAULT_BACKEND_UNAVAILABLE",
      });
    }
    if (!meta) {
      throw new VaultError("vault ref not found at getRetentionStatus", {
        vaultRef: ref,
        vaultBackendId: this.backendId,
        operation: "getRetentionStatus",
        reasonCode: "VAULT_REF_NOT_FOUND",
      });
    }
    return buildRetentionStatus({
      h_commit: ref,
      retention_expires_at: meta.retention_expires_at,
    });
  }

  async listExpired(asOf: string): Promise<readonly VaultRef[]> {
    try {
      return await this.store.listExpired(asOf);
    } catch {
      throw new VaultError("vault backend unavailable at listExpired", {
        vaultBackendId: this.backendId,
        operation: "listExpired",
        reasonCode: "VAULT_BACKEND_UNAVAILABLE",
      });
    }
  }
}
