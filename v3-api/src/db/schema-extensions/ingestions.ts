import {
  bigint,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
} from "drizzle-orm/pg-core";

export const ingestionsPhaseB = pgTable(
  "ingestions",
  {
    h_commit: text("h_commit").primaryKey(),
    authorization_id: text("authorization_id").notNull(),
    pda_id: text("pda_id").notNull(),
    pda_version: text("pda_version").notNull(),
    partner_id: text("partner_id").notNull(),
    subject_commitment_v3: text("subject_commitment_v3"),
    mode: text("mode").notNull().default("mode_a"),
    g4_phase: integer("g4_phase").notNull(),
    g3_choice: text("g3_choice").notNull(),
    schema_digest: text("schema_digest").notNull(),
    payload_classification: jsonb("payload_classification").notNull(),
    vault_blob_ref: text("vault_blob_ref").notNull(),
    commit_block: bigint("commit_block", { mode: "number" }),
    commit_block_hash: text("commit_block_hash"),
    commit_tx_hash: text("commit_tx_hash"),
    status: text("status").notNull(),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    anchored_at: timestamp("anchored_at", { withTimezone: true }),
    retention_expires_at: timestamp("retention_expires_at", { withTimezone: true }).notNull(),
  },
  (table) => ({
    partnerPdaIdx: index("ingestions_partner_pda_idx").on(table.partner_id, table.pda_id),
    authorizationIdx: index("ingestions_authorization_idx").on(table.authorization_id),
    statusIdx: index("ingestions_status_idx").on(table.status),
  }),
);

export const g4AttestationCachePhaseB = pgTable(
  "g4_attestation_cache",
  {
    cache_key: text("cache_key").primaryKey(),
    pda_id: text("pda_id").notNull(),
    authorization_id_candidate: text("authorization_id_candidate").notNull(),
    preflight_context_digest: text("preflight_context_digest").notNull(),
    commit_block: bigint("commit_block", { mode: "number" }).notNull(),
    commit_block_hash: text("commit_block_hash").notNull(),
    attestation_digest: text("attestation_digest").notNull(),
    attestation_json: jsonb("attestation_json").notNull(),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    pdaAuthorizationIdx: index("g4_attestation_cache_pda_auth_idx").on(
      table.pda_id,
      table.authorization_id_candidate,
    ),
  }),
);

