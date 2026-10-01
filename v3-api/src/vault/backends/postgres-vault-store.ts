// PostgresVaultStore — the atomic `VaultStore` over `vault_blobs` (0005) +
// the append-only `vault_audit_log` (0003). One row per blob: ciphertext,
// inseparable commit binding, and non-secret metadata are written, read, and
// deleted as ONE unit (C1). Crypto-shred deletes the row AND appends a shred
// row to the append-only audit log in the same transaction.
//
// GDPR discipline (NON-NEGOTIABLE):
//   - `ciphertext` is AEAD ciphertext ONLY. No plaintext, no DEK, ever — there
//     is no key column by construction.
//   - The shred-audit row carries NO PII: only the opaque ref, the PDA-configured
//     shred authority, and timestamps go into `safe_refs`.
//   - `vault_audit_log` is append-only (DB trigger raises on UPDATE/DELETE during
//     the retention window). This store only ever INSERTs into it.
//
// postgres-js maps `bytea` → Node `Buffer` on read; normalize to `Uint8Array`.
//
// V3 isolation (SECURITY.md): no @cealis/shared, no V1 packages, no
// V1 env vars. Caller injects the `postgres()` Sql client at the composition root.

import { randomUUID } from "node:crypto";
import type { Sql } from "postgres";
import type { VaultBackendId, VaultBlob, VaultBlobMeta, VaultRef } from "../cealis-v3-vault.js";
import type {
  VaultShredAuditRow,
  VaultStore,
  VaultStorePutResult,
  VaultStoreRecord,
} from "../vault-store.js";

export interface PostgresVaultStoreOptions {
  /** postgres-js Sql client bound to the V3 vault DB (`cealis_v3_dev`). */
  readonly sql: Sql;
  /**
   * Retention window (days) for a shred-audit row's `purge_after` — the only
   * legal purge path is `purge_old_audit_logs()` (12-month rolling). Default 365.
   */
  readonly auditLogRetentionDays?: number;
}

/** Normalize a postgres-js bytea read (`Buffer` | `Uint8Array`) to a plain
 *  `Uint8Array` so no Node `Buffer` subtype leaks across the storage boundary. */
function toUint8Array(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError("PostgresVaultStore: expected bytea bytes, got " + typeof value);
}

/** postgres-js may return a `jsonb` column as a parsed object OR a JSON string
 *  depending on the column's CAST path (we INSERT via `${str}::jsonb`). Normalize
 *  to the parsed object so the metadata shape is identical to the filesystem
 *  backend's. */
function normalizeJson(value: unknown): Record<string, unknown> {
  if (typeof value === "string") {
    return JSON.parse(value) as Record<string, unknown>;
  }
  return (value ?? {}) as Record<string, unknown>;
}

/** Constant-time-ish byte equality (length-checked then byte-wise). Used only
 *  for idempotent-put collision detection — not a secret comparison. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

interface VaultBlobRow {
  readonly ciphertext: unknown;
  readonly commit_aad_bytes: unknown;
  readonly commit_version_onwire: number;
  readonly commit_aad_digest: string;
  readonly payload_classification: unknown;
  readonly retention_policy_id: string;
  readonly retention_expires_at: Date;
  readonly byte_len: number;
  readonly created_at: Date;
}

export class PostgresVaultStore implements VaultStore {
  readonly backendId: VaultBackendId = "postgres-blob";
  private readonly sql: Sql;
  private readonly auditLogRetentionDays: number;

  constructor(options: PostgresVaultStoreOptions) {
    this.sql = options.sql;
    this.auditLogRetentionDays = options.auditLogRetentionDays ?? 365;
  }

  async putRecord(record: VaultStoreRecord): Promise<VaultStorePutResult> {
    const existing = await this.readRow(record.ref);
    if (existing) {
      // Idempotent: identical ciphertext AND identical binding bytes → no-op.
      const sameCiphertext = bytesEqual(toUint8Array(existing.ciphertext), record.ciphertext);
      const sameBinding = bytesEqual(
        toUint8Array(existing.commit_aad_bytes),
        record.commitBinding.commit_aad_bytes,
      );
      if (sameCiphertext && sameBinding) {
        return { stored: false, collision: false };
      }
      return { stored: false, collision: true };
    }

    // INSERT with ON CONFLICT DO NOTHING guards the racing-writer window: a
    // concurrent insert of the SAME bytes is a benign no-op; of DIFFERENT bytes
    // it is caught on the post-insert read-back below.
    const rows = await this.sql<{ vault_ref: string }[]>`
      INSERT INTO vault_blobs (
        vault_ref, ciphertext, commit_aad_bytes, commit_version_onwire,
        commit_aad_digest, payload_classification, retention_policy_id,
        retention_expires_at, byte_len, created_at
      ) VALUES (
        ${record.ref}, ${record.ciphertext}, ${record.commitBinding.commit_aad_bytes},
        ${record.commitBinding.commit_version_onwire}, ${record.commitBinding.commit_aad_digest},
        ${JSON.stringify(record.meta.payload_classification)}::jsonb, ${record.meta.retention_policy_id},
        ${new Date(record.meta.retention_expires_at)}, ${record.meta.byte_len},
        ${new Date(record.meta.created_at)}
      )
      ON CONFLICT (vault_ref) DO NOTHING
      RETURNING vault_ref
    `;
    if (rows.length > 0) {
      return { stored: true, collision: false };
    }
    // Lost the race: a row now exists. Re-read and decide no-op vs collision.
    const raced = await this.readRow(record.ref);
    if (!raced) {
      // Extremely unlikely (deleted between insert + read); treat as stored.
      return { stored: true, collision: false };
    }
    const sameCiphertext = bytesEqual(toUint8Array(raced.ciphertext), record.ciphertext);
    const sameBinding = bytesEqual(
      toUint8Array(raced.commit_aad_bytes),
      record.commitBinding.commit_aad_bytes,
    );
    return { stored: false, collision: !(sameCiphertext && sameBinding) };
  }

  async getRecord(ref: VaultRef): Promise<VaultBlob | undefined> {
    const row = await this.readRow(ref);
    if (!row) return undefined;
    return {
      ciphertext: toUint8Array(row.ciphertext),
      commitBinding: {
        commit_aad_bytes: toUint8Array(row.commit_aad_bytes),
        commit_version_onwire: row.commit_version_onwire,
        commit_aad_digest: row.commit_aad_digest,
      },
      meta: this.rowToMeta(row),
    };
  }

  async deleteRecord(audit: VaultShredAuditRow): Promise<boolean> {
    const purgeAfter = new Date(
      Date.parse(audit.shreddedAt) + this.auditLogRetentionDays * 24 * 60 * 60 * 1000,
    );
    // Atomic: delete the blob row + append the shred-audit row together. If the
    // blob did not exist, neither side commits (return false).
    const result = await this.sql.begin(async (tx) => {
      const deleted = await tx<{ vault_ref: string }[]>`
        DELETE FROM vault_blobs WHERE vault_ref = ${audit.ref} RETURNING vault_ref
      `;
      if (deleted.length === 0) {
        return false;
      }
      // safe_refs carries NO PII: opaque ref + PDA-configured shred authority +
      // timestamp only. String-serialize → ::jsonb cast (codebase idiom).
      const safeRefsJson = JSON.stringify({
        vault_ref: audit.ref,
        shred_authority: audit.shredAuthority,
        shredded_at: audit.shreddedAt,
      });
      await tx`
        INSERT INTO vault_audit_log (
          audit_id, actor_ref, action, h_commit, pda_id, safe_refs, created_at, purge_after
        ) VALUES (
          ${randomUUID()}, ${"vault:" + audit.shredAuthority}, ${"vault_shred"},
          ${audit.ref}, ${null},
          ${safeRefsJson}::jsonb,
          ${new Date(audit.shreddedAt)}, ${purgeAfter}
        )
      `;
      return true;
    });
    return result;
  }

  async getMeta(ref: VaultRef): Promise<VaultBlobMeta | undefined> {
    const rows = await this.sql<Omit<VaultBlobRow, "ciphertext" | "commit_aad_bytes">[]>`
      SELECT commit_version_onwire, commit_aad_digest, payload_classification,
             retention_policy_id, retention_expires_at, byte_len, created_at
      FROM vault_blobs WHERE vault_ref = ${ref}
    `;
    const row = rows[0];
    if (!row) return undefined;
    return this.rowToMeta(row);
  }

  async listExpired(asOf: string): Promise<readonly VaultRef[]> {
    const cutoff = new Date(asOf);
    const rows = await this.sql<{ vault_ref: string }[]>`
      SELECT vault_ref FROM vault_blobs WHERE retention_expires_at <= ${cutoff}
    `;
    return rows.map((r) => r.vault_ref);
  }

  private async readRow(ref: VaultRef): Promise<VaultBlobRow | undefined> {
    const rows = await this.sql<VaultBlobRow[]>`
      SELECT ciphertext, commit_aad_bytes, commit_version_onwire, commit_aad_digest,
             payload_classification, retention_policy_id, retention_expires_at,
             byte_len, created_at
      FROM vault_blobs WHERE vault_ref = ${ref}
    `;
    return rows[0];
  }

  private rowToMeta(
    row: Omit<VaultBlobRow, "ciphertext" | "commit_aad_bytes">,
  ): VaultBlobMeta {
    return {
      payload_classification: normalizeJson(row.payload_classification),
      retention_policy_id: row.retention_policy_id,
      retention_expires_at: row.retention_expires_at.toISOString(),
      byte_len: row.byte_len,
      created_at: row.created_at.toISOString(),
    };
  }
}
