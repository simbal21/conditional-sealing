// Phase 3 runtime-storage tables — vault ciphertext blobs + wrapped DEK shares.
//
// These back the real off-chain runtime (T0.3 vault impl, T1.2 vault writer,
// T4.2 crypto-shred cascade). They are NOT part of the Phase-A locked 17-table
// API catalog (`V3_API_TABLE_NAMES` in schema.ts) — that catalog is the public
// API surface and stays frozen at 17. These are internal storage tables; their
// canonical name list lives in `V3_RUNTIME_STORAGE_TABLE_NAMES` (schema.ts).
//
// Migration ownership (single source of truth = the SQL):
//   * `vault_blobs`        → migrations/0005_vault_blobs.sql        (T0.3)
//   * `dek_share_records`  → migrations/0006_dek_share_records.sql  (T0.1)
// These Drizzle definitions MIRROR the DDL above — if they drift, the
// 0006 migration test (and any repository) breaks. Keep them in lockstep.
//
// GDPR / legal discipline (internal legal-constraints rules, D3 retention):
//   - `vault_blobs.ciphertext` is the ONLY place PII lives, and only as
//     AEAD/ECIES ciphertext under the DEK. The vault NEVER holds the DEK and
//     has no key column by construction.
//   - `commit_aad_bytes` is inseparable from the ciphertext (C1 commit
//     binding): stored in the same row, returned only alongside the ciphertext.
//   - `dek_share_records` rows ARE key material. Crypto-shred = destroy these
//     rows + delete the vault blob; post-shred the plaintext is unrecoverable
//     (Art. 17 right to erasure). Each row carries the 39-byte ShareRecord
//     SCALE encoding (§6.3.2), held wrapped — never a plaintext DEK and never a
//     standalone-reconstructing plaintext share.
//   - `retention_expires_at` is populated at ingest with the PDA's retention
//     floor (vault ciphertext = obligation duration + 3y, §195 BGB). The
//     retention worker (T4.3) reads it to schedule policy-driven shred.
//
// V3 isolation: no @cealis/shared imports, no V1 schema reuse, separate DB
// (`cealis_v3_dev`). Same column-type idiom as ingestions/reveals/auth.

import {
  customType,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  smallint,
  text,
  timestamp,
} from "drizzle-orm/pg-core";

/**
 * Postgres `bytea` column mapped to a Node `Buffer` in/out.
 *
 * drizzle-orm 0.36 has no first-class `bytea` helper for postgres-js, so we
 * declare it via `customType`. postgres-js already round-trips `Buffer` <->
 * `bytea` over the wire; this only labels the column DDL + the TS type.
 */
export const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
});

/**
 * Vault ciphertext blob store — opaque, backend-agnostic metadata row.
 *
 * MIRRORS migrations/0005_vault_blobs.sql (owned by T0.3). One row per sealed
 * payload. `ciphertext` is AEAD output under the DEK; the vault stores and
 * retrieves only, it never decrypts. `commit_aad_bytes` +
 * `commit_version_onwire` + `commit_aad_digest` reproduce the commit binding so
 * a reader can verify inseparability (C1) before opening.
 */
export const vaultBlobsTable = pgTable(
  "vault_blobs",
  {
    vault_ref: text("vault_ref").primaryKey(),
    ciphertext: bytea("ciphertext").notNull(),
    commit_aad_bytes: bytea("commit_aad_bytes").notNull(),
    commit_version_onwire: integer("commit_version_onwire").notNull(),
    commit_aad_digest: text("commit_aad_digest").notNull(),
    payload_classification: jsonb("payload_classification").notNull(),
    retention_policy_id: text("retention_policy_id").notNull(),
    retention_expires_at: timestamp("retention_expires_at", { withTimezone: true }).notNull(),
    byte_len: integer("byte_len").notNull(),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("vault_blobs_retention_expires_at_idx").on(table.retention_expires_at)],
);

/**
 * WRAPPED per-gate DEK share stanzas — key material, crypto-shred target.
 *
 * MIRRORS migrations/0006_dek_share_records.sql (owned by T0.1). Each row is one
 * §6.2 hybrid-wrap stanza: `wrapped_payload` (1168 bytes = pk_eph ‖ ct_mlkem ‖
 * wrapped_share) decryptable ONLY by that gate's private key, plus the routing
 * metadata (stanza_index / gate_kind / role / domain / logical_index / x /
 * binding_tag) the reveal path uses to route a gate to its stanza and rebuild a
 * typed ShareRecord after unwrap. NON-CUSTODY: never a raw reconstructable share.
 * The shred executor (T4.2) deletes these rows to satisfy Art. 17.
 * Composite PK (h_commit, stanza_index) so a commit's full stanza set is one query.
 */
export const dekShareRecordsTable = pgTable(
  "dek_share_records",
  {
    h_commit: text("h_commit").notNull(),
    stanza_index: integer("stanza_index").notNull(),
    gate_kind: smallint("gate_kind").notNull(),
    conditional_recipient_index: integer("conditional_recipient_index").notNull(),
    role: smallint("role").notNull(),
    domain: smallint("domain").notNull(),
    logical_index: integer("logical_index").notNull(),
    x: integer("x").notNull(),
    binding_tag: text("binding_tag").notNull(),
    wrapped_payload: bytea("wrapped_payload").notNull(),
    plugin_version_digest: bytea("plugin_version_digest").notNull(),
    commit_context_digest_n: bytea("commit_context_digest_n").notNull(),
    commit_context_digest_0: bytea("commit_context_digest_0").notNull(),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({
      columns: [table.h_commit, table.stanza_index],
    }),
    index("dek_share_records_h_commit_idx").on(table.h_commit),
  ],
);
