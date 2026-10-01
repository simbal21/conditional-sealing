// Drizzle DB schema — table name + relation list ONLY at Phase A.
//
// LOCKED at Phase A. Column types + indexes + triggers are filled by
// Phase B/C/D per the chunk's owned tables. Migrations land at:
//   src/db/migrations/0001_ingestions.sql  (Phase B owns)
//   src/db/migrations/0002_reveals.sql      (Phase C owns)
//   src/db/migrations/0003_auth_webhooks.sql (Phase D owns)
//
// Cross-chunk discipline: Phase A locks the table name list so Phase B writes
// `ingestions` (not `ingestion_records`), Phase C writes `reveals`, Phase D
// writes `webhook_deliveries`. Drift caught at Phase F.
//
// V3 separation: per `SECURITY.md`, V3 uses a NEW database
// (`cealis_v3_dev` local; separate Railway Postgres production). No FK across
// to V1 `cealis_dev`.

import { pgTable, text } from "drizzle-orm/pg-core";

// ===========================================================================
// Phase B owns: ingestions + pre_sigma_sessions + g4_attestation_cache
// ===========================================================================

/**
 * Ingestions table — V3 namespace (replaces V1 `onboardings`).
 *
 * Owned by Phase B. Phase B fills column types in
 * `src/db/schema-extensions/ingestions.ts` and migration
 * `src/db/migrations/0001_ingestions.sql`.
 *
 * Required columns (Phase B will type):
 *   h_commit (pk, bytea 32), authorization_id, pda_id, pda_version,
 *   partner_id, subject_commitment_v3, mode (mode_a only), g4_phase,
 *   g3_choice, schema_digest, payload_classification, vault_blob_ref,
 *   commit_block, commit_block_hash, commit_tx_hash, status, created_at,
 *   anchored_at, retention_expires_at.
 */
export const ingestions = pgTable("ingestions", {
  _phase_b_placeholder: text("_phase_b_placeholder"),
});

/**
 * Pre-σ sessions — §6.3 binds confirmation → subsequent ingestion.
 *
 * Owned by Phase D (subject API) and read by Phase B (consumed at ingest time).
 *
 * Required columns (Phase D will type):
 *   session_id (pk), onboarding_link_id, partner_id, pda_id, subject_user_id,
 *   pre_sigma_payload_digest, confirmations_completed_at, consumed_at,
 *   created_at, expires_at.
 */
export const pre_sigma_sessions = pgTable("pre_sigma_sessions", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * G4 attestation cache — per-commit pre-flight attestation candidates.
 *
 * Owned by Phase B. Caches `GET /v1/g4/attestation` responses keyed by
 * (pda_id, authorizationIdCandidate).
 */
export const g4_attestation_cache = pgTable("g4_attestation_cache", {
  _phase_b_placeholder: text("_phase_b_placeholder"),
});

// ===========================================================================
// Phase C owns: reveals + event_cursors + g4_refusals
// ===========================================================================

/**
 * Reveals table — per-recipient reveal delivery state.
 *
 * Owned by Phase C. Phase C fills column types in
 * `src/db/schema-extensions/reveals.ts` and migration
 * `src/db/migrations/0002_reveals.sql`.
 *
 * Required columns (Phase C will type):
 *   authorization_id (pk), h_commit, recipient_ref, bundle_digest,
 *   bundle_storage_ref, status, finalized_at, challenge_window_expired_at,
 *   created_at.
 */
export const reveals = pgTable("reveals", {
  _phase_c_placeholder: text("_phase_c_placeholder"),
});

/**
 * Event cursors — M2 RevealAuthorized listener tip per chain_id.
 *
 * Owned by Phase C.
 */
export const event_cursors = pgTable("event_cursors", {
  _phase_c_placeholder: text("_phase_c_placeholder"),
});

/**
 * G4 refusals — 10-code enum entries + reason_visibility discriminator.
 *
 * Owned by Phase C (refusal-handler) and read by Phase D (webhook emitter).
 *
 * Required columns (Phase C will type):
 *   refusal_id (pk), authorization_id, h_commit, reason_code (smallint),
 *   reason_label, reason_visibility (text enum), encrypted_reason_ref,
 *   refused_at.
 */
export const g4_refusals = pgTable("g4_refusals", {
  _phase_c_placeholder: text("_phase_c_placeholder"),
});

// ===========================================================================
// Phase D owns: partners + user_accounts + user_sessions + idempotency_keys +
//                onboarding_links + partner_agreements + webhook_deliveries +
//                vault_audit_log + push_subscriptions
// ===========================================================================

/**
 * Partners — API credentials + scopes + signing secrets.
 *
 * Owned by Phase D. Per BP-N-S2-5-3 (auth schema split), separate columns for
 * api_key_bcrypt, signing_secret_encrypted, webhook_secret_encrypted.
 *
 * Required columns (Phase D will type):
 *   partner_id (pk uuid), name, api_key_id, api_key_bcrypt,
 *   signing_secret_encrypted, scopes (text[]), webhook_secret_encrypted,
 *   created_at, revoked_at.
 */
export const partners = pgTable("partners", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * User accounts — subject passkey anchor.
 */
export const user_accounts = pgTable("user_accounts", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * User sessions — SHA-256 hashed Bearer, 7-day expiry, revocable (§6.1).
 */
export const user_sessions = pgTable("user_sessions", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * Idempotency keys — V1 carry, 24h TTL (§1.5).
 */
export const idempotency_keys = pgTable("idempotency_keys", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * Onboarding links — V1 carry, token-bearing URL (§2.7 + §6.3).
 */
export const onboarding_links = pgTable("onboarding_links", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * Partner agreements — one active PDA per partner (V1 carry).
 */
export const partner_agreements = pgTable("partner_agreements", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * Webhook deliveries — BullMQ shadow, 90d retention (§15.3).
 */
export const webhook_deliveries = pgTable("webhook_deliveries", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * Vault audit log — append-only via DB trigger (§15.2 + legal-constraints.md
 * append-only invariant — V1 trigger pattern carried).
 */
export const vault_audit_log = pgTable("vault_audit_log", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * Push subscriptions — web-push (V1 carry).
 */
export const push_subscriptions = pgTable("push_subscriptions", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * HMAC replay-nonce window (R2b LBU swap). Pure crypto-replay catalog —
 * no PII, no retention/legal semantics. Real column types live in
 * `src/db/schema-extensions/auth.ts` (`noncesAuth`); migration
 * `src/db/migrations/0004_auth_replay_and_ratelimit.sql`.
 */
export const nonces = pgTable("nonces", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

/**
 * Per-credential rate-limit buckets (R2b LBU swap). Pure ops catalog —
 * no PII, no retention/legal semantics. Real column types live in
 * `src/db/schema-extensions/auth.ts` (`rateLimitBucketsAuth`); migration
 * `src/db/migrations/0004_auth_replay_and_ratelimit.sql`.
 */
export const rate_limit_buckets = pgTable("rate_limit_buckets", {
  _phase_d_placeholder: text("_phase_d_placeholder"),
});

// ===========================================================================
// Canonical table name catalog — Phase A foundation test asserts this list
// matches the exported table objects above.
// ===========================================================================

export const V3_API_TABLE_NAMES = [
  // Phase B owned
  "ingestions",
  "pre_sigma_sessions",
  "g4_attestation_cache",
  // Phase C owned
  "reveals",
  "event_cursors",
  "g4_refusals",
  // Phase D owned
  "partners",
  "user_accounts",
  "user_sessions",
  "idempotency_keys",
  "onboarding_links",
  "partner_agreements",
  "webhook_deliveries",
  "vault_audit_log",
  "push_subscriptions",
  // R2b LBU swap (operational catalog, no legal semantics)
  "nonces",
  "rate_limit_buckets",
] as const;

export type V3ApiTableName = (typeof V3_API_TABLE_NAMES)[number];

export const V3_API_TABLE_COUNT: number = V3_API_TABLE_NAMES.length;

// ===========================================================================
// Phase 3 runtime-storage tables — vault ciphertext + wrapped DEK shares.
//
// These are INTERNAL storage tables added by the Phase-3 real-runtime build
// (migrations 0005 vault_blobs + 0006 dek_share_records). They are deliberately
// SEPARATE from the Phase-A locked API catalog above: `V3_API_TABLE_NAMES` is
// the frozen 29-operation API surface (17 tables) and must not grow. Runtime
// storage tables live in their own catalog so adding them never perturbs the
// locked API count. Real column types: `schema-extensions/vault-blobs.ts`.
// ===========================================================================

export const V3_RUNTIME_STORAGE_TABLE_NAMES = [
  "vault_blobs",
  "dek_share_records",
] as const;

export type V3RuntimeStorageTableName = (typeof V3_RUNTIME_STORAGE_TABLE_NAMES)[number];

export const V3_RUNTIME_STORAGE_TABLE_COUNT: number = V3_RUNTIME_STORAGE_TABLE_NAMES.length;
