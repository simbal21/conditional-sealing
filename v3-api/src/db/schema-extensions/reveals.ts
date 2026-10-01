import {
  bigint,
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  smallint,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

export const revealsTable = pgTable(
  "reveals",
  {
    authorizationId: text("authorization_id").notNull(),
    hCommit: text("h_commit").notNull(),
    recipientRef: text("recipient_ref").notNull(),
    bundleDigest: text("bundle_digest"),
    bundleStorageRef: text("bundle_storage_ref"),
    status: text("status").notNull(),
    g4Phase: smallint("g4_phase").notNull(),
    manifest: jsonb("manifest"),
    bundle: jsonb("bundle"),
    finalizedAt: timestamp("finalized_at", { withTimezone: true }),
    challengeWindowExpiredAt: timestamp("challenge_window_expired_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => ({
    pk: primaryKey({ columns: [table.authorizationId, table.recipientRef] }),
    hCommitIdx: index("reveals_h_commit_idx").on(table.hCommit),
    statusIdx: index("reveals_status_idx").on(table.status),
  }),
);

export const eventCursorsTable = pgTable(
  "event_cursors",
  {
    chainId: integer("chain_id").notNull(),
    contractAddress: text("contract_address").notNull(),
    eventName: text("event_name").notNull(),
    lastProcessedBlock: bigint("last_processed_block", { mode: "bigint" }).notNull(),
    lastProcessedLogIndex: integer("last_processed_log_index").default(0).notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => ({
    pk: primaryKey({
      columns: [table.chainId, table.contractAddress, table.eventName],
    }),
  }),
);

export const g4RefusalsTable = pgTable(
  "g4_refusals",
  {
    refusalId: text("refusal_id").primaryKey(),
    authorizationId: text("authorization_id").notNull(),
    hCommit: text("h_commit").notNull(),
    partnerId: uuid("partner_id").notNull(),
    pdaId: uuid("pda_id").notNull(),
    reasonCode: smallint("reason_code").notNull(),
    reasonCodeHex: text("reason_code_hex").notNull(),
    reasonLabel: text("reason_label").notNull(),
    reasonVisibility: text("reason_visibility").notNull(),
    encryptedReasonRef: text("encrypted_reason_ref"),
    blocking: boolean("blocking").notNull(),
    refusedAt: timestamp("refused_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => ({
    authorizationIdx: index("g4_refusals_authorization_idx").on(table.authorizationId),
    hCommitIdx: index("g4_refusals_h_commit_idx").on(table.hCommit),
  }),
);
