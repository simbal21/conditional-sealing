// @cealis/v3-api db barrel.
//
// Phase A: schema (table names + relations) only.
// Phase B/C/D: column types + migrations.
// Phase F: connection helper + Drizzle migration runner.
// Phase 3 (T0.1): real getDb() + runMigrations() + the runtime-storage
//   schema extension (vault_blobs + dek_share_records).

export * from "./schema.js";

// Phase 3 — real Postgres connection + migration runner.
export * from "./connection.js";
export * from "./migrate.js";

// Phase 3 — runtime-storage tables (vault ciphertext + wrapped DEK shares).
// Re-exported here so the composition root + repositories import from the db
// barrel. NOT added to the Phase-A locked API catalog (`V3_API_TABLE_NAMES`).
export * from "./schema-extensions/vault-blobs.js";
