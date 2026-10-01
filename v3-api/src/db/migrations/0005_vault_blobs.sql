-- T0.3 — Real CealisV3Vault storage backend (Phase 3 runtime).
-- Source: docs/specs/ingestion-delivery-api-spec.md (vault sections) + S2-3
-- storage discipline + internal legal-constraints rules, not exported (D3 retention).
--
-- GDPR discipline (NON-NEGOTIABLE):
--   * `vault_blobs` holds AEAD CIPHERTEXT ONLY. Never plaintext, never the DEK,
--     never a wrapped DEK share (shares live in their own table, separate seam).
--   * The vault never decrypts — there is no key column here by construction.
--   * `commit_aad_bytes` is INSEPARABLE from the ciphertext (C1): it is stored in
--     the SAME row and only ever returned alongside the ciphertext, so the
--     combiner's unconditional commitAAD round-trip cannot be defeated by
--     consuming ciphertext without its binding.
--   * Crypto-shred (right-to-erasure) = DELETE the row here + append a shred row
--     to the append-only `vault_audit_log` (0003). On-chain commitment becomes an
--     orphan. The DEK-share destruction is M1/M3's part, not the vault's.
--   * Retention: `retention_expires_at` = obligation duration + 3y (§195 BGB);
--     populated at ingest with the PDA's retention floor. The retention worker
--     (T4.3) reads `listExpired` off this column.
--
-- V3 isolation (SECURITY.md): new table in `cealis_v3_dev`. No FK to
-- V1 `cealis_dev`. No `vault_audit_log` schema change here — shred rows reuse the
-- existing append-only table from 0003.

CREATE TABLE IF NOT EXISTS vault_blobs (
  -- Opaque, collision-free vault ref. Scheme is the caller's concern
  -- (e.g. `vault://{h_commit}` for ingestion ciphertext); the vault treats it
  -- as an opaque key and never parses it for semantics.
  vault_ref TEXT PRIMARY KEY,

  -- AEAD ciphertext. CIPHERTEXT ONLY — no plaintext, no DEK, ever.
  ciphertext BYTEA NOT NULL,

  -- C1 inseparable commit binding. FULL raw on-wire commit_AAD bytes (the input
  -- the combiner re-encodes + byte-compares), stored in the SAME row.
  commit_aad_bytes BYTEA NOT NULL,
  -- Raw on-wire commit_version read at the canonical offset (NEVER the
  -- post-decode/patched value — using the patched value is the confirmed C1 defeat).
  commit_version_onwire INTEGER NOT NULL,
  -- On-chain commitment digest the re-encoded commit_AAD is bound against.
  commit_aad_digest TEXT NOT NULL,

  -- Non-secret metadata (contains NO key/DEK/plaintext).
  payload_classification JSONB NOT NULL,
  retention_policy_id TEXT NOT NULL,
  retention_expires_at TIMESTAMPTZ NOT NULL,
  byte_len INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vault_blobs_retention_expires_at_idx
  ON vault_blobs (retention_expires_at);
