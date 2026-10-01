import { index, integer, jsonb, pgTable, text, timestamp, uuid, boolean } from "drizzle-orm/pg-core";

export const partnersAuth = pgTable(
  "partners",
  {
    partner_id: uuid("partner_id").primaryKey(),
    name: text("name").notNull(),
    api_key_id: text("api_key_id").notNull().unique(),
    api_key_bcrypt: text("api_key_bcrypt").notNull(),
    signing_secret_encrypted: text("signing_secret_encrypted").notNull(),
    scopes: text("scopes").array().notNull(),
    webhook_secret_encrypted: text("webhook_secret_encrypted").notNull(),
    webhook_url: text("webhook_url"),
    rate_limit_per_second: integer("rate_limit_per_second").notNull().default(10),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    revoked_at: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [index("partners_api_key_id_idx").on(table.api_key_id)],
);

export const userAccountsAuth = pgTable("user_accounts", {
  user_id: uuid("user_id").primaryKey(),
  subject_namespace: text("subject_namespace").notNull(),
  passkey_credential_digest: text("passkey_credential_digest").notNull(),
  created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const userSessionsAuth = pgTable(
  "user_sessions",
  {
    session_id: uuid("session_id").primaryKey(),
    user_id: uuid("user_id").notNull(),
    token_hash: text("token_hash").notNull().unique(),
    expires_at: timestamp("expires_at", { withTimezone: true }).notNull(),
    revoked_at: timestamp("revoked_at", { withTimezone: true }),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("user_sessions_token_hash_idx").on(table.token_hash)],
);

export const idempotencyKeysAuth = pgTable(
  "idempotency_keys",
  {
    scope: text("scope").notNull(),
    idempotency_key: text("idempotency_key").notNull(),
    request_digest: text("request_digest").notNull(),
    response_status: integer("response_status").notNull(),
    response_body: jsonb("response_body").notNull(),
    expires_at: timestamp("expires_at", { withTimezone: true }).notNull(),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("idempotency_keys_scope_key_idx").on(table.scope, table.idempotency_key),
    index("idempotency_keys_expires_at_idx").on(table.expires_at),
  ],
);

// HMAC nonce replay-window store. Pure crypto-replay catalog — NO PII, no
// retention/legal semantics. Per ADJ-2 STOP-gate review: existing-catalog
// extension class (green), not legally-load-bearing.
//
// Key (key_id, nonce) is unique; rows TTL via expires_at and are purged by a
// background sweeper (or on-write lazy purge in the Postgres store impl).
export const noncesAuth = pgTable(
  "nonces",
  {
    key_id: text("key_id").notNull(),
    nonce: text("nonce").notNull(),
    expires_at: timestamp("expires_at", { withTimezone: true }).notNull(),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("nonces_key_id_nonce_idx").on(table.key_id, table.nonce),
    index("nonces_expires_at_idx").on(table.expires_at),
  ],
);

// Per-credential rate-limit buckets (fixed-window). Pure ops catalog —
// NO PII, no retention/legal semantics. Existing-catalog class (green).
//
// Bucket key is opaque to the schema; the store impl composes it (e.g.,
// `${partnerId}:${route}`). Rows survive for their window and are cleared
// on-write or by sweeper.
export const rateLimitBucketsAuth = pgTable(
  "rate_limit_buckets",
  {
    bucket_key: text("bucket_key").primaryKey(),
    count: integer("count").notNull(),
    reset_at: timestamp("reset_at", { withTimezone: true }).notNull(),
    updated_at: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("rate_limit_buckets_reset_at_idx").on(table.reset_at)],
);

export const onboardingLinksAuth = pgTable(
  "onboarding_links",
  {
    onboarding_link_id: uuid("onboarding_link_id").primaryKey(),
    partner_id: uuid("partner_id").notNull(),
    pda_id: text("pda_id").notNull(),
    token_hash: text("token_hash").notNull().unique(),
    label: text("label"),
    active: boolean("active").notNull().default(true),
    max_uses: integer("max_uses"),
    used_count: integer("used_count").notNull().default(0),
    redirect_url: text("redirect_url"),
    subject_hint_ref: text("subject_hint_ref"),
    expires_at: timestamp("expires_at", { withTimezone: true }),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("onboarding_links_partner_pda_idx").on(table.partner_id, table.pda_id)],
);

export const partnerAgreementsAuth = pgTable(
  "partner_agreements",
  {
    partner_agreement_id: uuid("partner_agreement_id").primaryKey(),
    partner_id: uuid("partner_id").notNull(),
    pda_id: text("pda_id").notNull(),
    status: text("status").notNull(),
    effective_at: timestamp("effective_at", { withTimezone: true }).notNull(),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("partner_agreements_partner_pda_idx").on(table.partner_id, table.pda_id)],
);

export const webhookDeliveriesAuth = pgTable(
  "webhook_deliveries",
  {
    delivery_id: uuid("delivery_id").primaryKey(),
    event_id: text("event_id").notNull(),
    event_type: text("event_type").notNull(),
    partner_id: uuid("partner_id").notNull(),
    pda_id: text("pda_id").notNull(),
    delivery_url_digest: text("delivery_url_digest").notNull(),
    attempt_count: integer("attempt_count").notNull().default(0),
    status_code: integer("status_code"),
    final_state: text("final_state").notNull(),
    dead_letter_ref: text("dead_letter_ref"),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expires_at: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [
    index("webhook_deliveries_event_idx").on(table.event_id),
    index("webhook_deliveries_expires_at_idx").on(table.expires_at),
  ],
);

export const vaultAuditLogAuth = pgTable(
  "vault_audit_log",
  {
    audit_id: uuid("audit_id").primaryKey(),
    actor_ref: text("actor_ref").notNull(),
    action: text("action").notNull(),
    h_commit: text("h_commit").notNull(),
    partner_id: uuid("partner_id"),
    pda_id: text("pda_id"),
    safe_refs: jsonb("safe_refs").notNull(),
    created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    purge_after: timestamp("purge_after", { withTimezone: true }).notNull(),
  },
  (table) => [index("vault_audit_log_h_commit_idx").on(table.h_commit)],
);

export const pushSubscriptionsAuth = pgTable("push_subscriptions", {
  subscription_id: uuid("subscription_id").primaryKey(),
  user_id: uuid("user_id").notNull(),
  endpoint_digest: text("endpoint_digest").notNull(),
  encrypted_subscription_ref: text("encrypted_subscription_ref").notNull(),
  created_at: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  revoked_at: timestamp("revoked_at", { withTimezone: true }),
});
