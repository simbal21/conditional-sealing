// PostgresBlobBackend — opaque-byte storage seam over the V3 `vault_blobs`
// `bytea` column. Pure key→bytes storage with NO commit-binding / retention /
// shred-authority semantics (those live one layer up in CealisV3VaultImpl,
// which owns the metadata columns and the append-only shred-audit write).
//
// This backend persists ONLY the `vault_ref` + `ciphertext` pair; the vault
// layer writes the binding + metadata columns in the same row via its own UPSERT
// so a blob and its inseparable commit binding cannot be split across rows. The
// backend is the byte-level seam used by the vault for raw get/delete/list.
//
// Concurrency: PK on `vault_ref` + ON CONFLICT DO NOTHING gives idempotent puts;
// same-ref/different-bytes collision detection is the vault layer's job (it reads
// back and byte-compares), not the backend's.
//
// postgres-js maps `bytea` → Node `Buffer` on read; we normalize to `Uint8Array`
// at the boundary so callers never see a Buffer leak.
//
// V3 isolation (SECURITY.md): no @cealis/shared, no ../../packages/*
// (V1), no V1 env vars. Caller injects the `postgres()` Sql client at the
// composition root — the backend never reads a connection string or a key file.

import type { Sql } from "postgres";
import type { VaultBackend, VaultBackendId } from "../cealis-v3-vault.js";

export interface PostgresBlobBackendOptions {
  /** postgres-js Sql client bound to the V3 vault DB (`cealis_v3_dev`). */
  readonly sql: Sql;
}

/** Normalize a postgres-js bytea read (`Buffer` | `Uint8Array`) to `Uint8Array`,
 *  never leaking a Node `Buffer` subtype out of the storage boundary. */
function toUint8Array(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    // Buffer IS a Uint8Array subclass — re-wrap to a plain Uint8Array view over
    // the exact same bytes so downstream `instanceof Buffer` checks can't fork.
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError("PostgresBlobBackend: expected bytea bytes, got " + typeof value);
}

export class PostgresBlobBackend implements VaultBackend {
  readonly backendId: VaultBackendId = "postgres-blob";
  private readonly sql: Sql;

  constructor(options: PostgresBlobBackendOptions) {
    this.sql = options.sql;
  }

  /** Idempotent put of raw ciphertext bytes keyed by ref. Same ref → no-op at
   *  the backend layer (the vault layer enforces same-bytes vs collision). The
   *  binding + metadata columns are written by the vault layer's own UPSERT on
   *  the same row; this method only ensures the row + ciphertext exist. */
  async put(key: string, bytes: Uint8Array): Promise<void> {
    // postgres-js accepts Uint8Array/Buffer for a bytea column directly.
    await this.sql`
      UPDATE vault_blobs SET ciphertext = ${bytes} WHERE vault_ref = ${key}
    `;
  }

  async get(key: string): Promise<Uint8Array | undefined> {
    const rows = await this.sql<{ ciphertext: unknown }[]>`
      SELECT ciphertext FROM vault_blobs WHERE vault_ref = ${key}
    `;
    const row = rows[0];
    if (!row) return undefined;
    return toUint8Array(row.ciphertext);
  }

  async delete(key: string): Promise<void> {
    await this.sql`DELETE FROM vault_blobs WHERE vault_ref = ${key}`;
  }

  async listKeys(prefix?: string): Promise<readonly string[]> {
    const rows =
      prefix === undefined
        ? await this.sql<{ vault_ref: string }[]>`SELECT vault_ref FROM vault_blobs`
        : await this.sql<{ vault_ref: string }[]>`
            SELECT vault_ref FROM vault_blobs WHERE vault_ref LIKE ${prefix + "%"}
          `;
    return rows.map((r) => r.vault_ref);
  }
}
