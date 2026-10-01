-- Phase 3 runtime storage — WRAPPED per-gate DEK share stanzas.
-- Source: internal Phase-3 runtime plan (not exported) §2 (dek_share_records) +
-- S2-1 cryptography-spec.md §6.2.3 (per-stanza hybrid-PQ wrap) + §6.3.2
-- (ShareRecord metadata) + internal design record dek-lifecycle.md Component #3.
--
-- Companion to migrations/0005_vault_blobs.sql: 0005 holds the age-envelope
-- ciphertext, 0006 holds the WRAPPED DEK share stanzas. They are deliberately
-- SEPARATE seams — the vault never sees an unwrapped share, the share table never
-- sees the payload plaintext.
--
-- NON-CUSTODY INVARIANT (the load-bearing property this table enforces):
--   * `wrapped_payload` is the §6.2 hybrid-wrap output for ONE gate — pk_eph_x25519
--     ‖ ct_mlkem ‖ wrapped_share (an ML-KEM-768 + X25519 HPKE envelope). It is
--     decryptable ONLY by that gate's private key (held in the gate's TEE /
--     threshold network, NEVER server-side).
--   * A single gate's share is information-theoretically zero on the DEK (Shamir).
--     The server holding EVERY row here but no gate private key cannot reconstruct
--     the DEK — that is the cryptographic enforcement of "no single party, not even
--     Cealis, can open it."
--   * NEVER store a raw 32-byte reconstructable share here. The byte length of a
--     wrapped payload (1168 = 32 + 1088 + 48) is intentionally far from a raw
--     39-byte ShareRecord — the CHECK below makes a raw-share write fail loud.
--
-- GDPR / legal (internal legal-constraints rules, not exported; D3 + crypto-shred):
--   * Rows here ARE key material (wrapped). Crypto-shred (Art. 17) = DELETE the
--     rows for an h_commit here + delete the vault blob (0005) + append a shred row
--     to the append-only vault_audit_log (0003). Post-shred the plaintext is
--     unrecoverable; on-chain commitment becomes an orphan.
--   * Retention: stanzas share the vault ciphertext lifetime (obligation duration +
--     3y §195 BGB) and are destroyed together at shred time.
-- V3 DB namespace only (cealis_v3_dev). No FK across to V1 cealis_dev.
--
-- 0006 evolution note (F-WRAP-1): the prior shape stored a RAW 39-byte ShareRecord
-- in `share_bytes` (octet_length = 39). That violated the non-custody invariant —
-- the server alone held reconstructable shares. This migration replaces it with the
-- WRAPPED stanza shape. Phase 3 is testnet-frozen with no production data, so the
-- table is dropped + recreated rather than ALTER-migrated.

DROP TABLE IF EXISTS dek_share_records;

CREATE TABLE IF NOT EXISTS dek_share_records (
  h_commit TEXT NOT NULL CHECK (h_commit ~ '^0x[0-9a-fA-F]{64}$'),
  -- Canonical stanza index in the age envelope (Lit=0, G3=1, G4=2, conditional=3+i).
  stanza_index INTEGER NOT NULL CHECK (stanza_index >= 0),
  -- GateKind (M2 Enums.sol): 0=Lit, 1=Dcipher, 2=Drand, 3=G4, 4=ConditionalRecipient.
  gate_kind SMALLINT NOT NULL CHECK (gate_kind BETWEEN 0 AND 4),
  -- 0 for top-level gates; the recipient slot index for conditional recipients.
  conditional_recipient_index INTEGER NOT NULL CHECK (conditional_recipient_index >= 0),
  -- ShareRecord routing metadata (rebuilt into a typed share after unwrap).
  -- SHARE_ROLE_* : 1=LIT, 2=G3, 3=G4, 4=RECIPIENT_AGGREGATE, 5=CONDITIONAL_RECIPIENT
  role SMALLINT NOT NULL CHECK (role BETWEEN 1 AND 5),
  -- SHARE_DOMAIN_* : 1=TOP_LEVEL, 2=RECIPIENT_BRANCH
  domain SMALLINT NOT NULL CHECK (domain IN (1, 2)),
  -- ShareRecord logical_index (zero-based) and x-coordinate (x = 0 is reserved-invalid).
  logical_index INTEGER NOT NULL CHECK (logical_index >= 0),
  x INTEGER NOT NULL CHECK (x >= 1),
  -- §6.2 domain-separation binding tag for this gate's stanza (0x + 64 hex).
  binding_tag TEXT NOT NULL CHECK (binding_tag ~ '^0x[0-9a-fA-F]{64}$'),
  -- §6.2 WRAPPED stanza payload: pk_eph_x25519 (32) ‖ ct_mlkem (1088) ‖
  -- wrapped_share AEAD ciphertext (48) = 1168 bytes. Held WRAPPED only — a raw
  -- 39-byte share write fails this CHECK loud (non-custody guardrail).
  wrapped_payload BYTEA NOT NULL CHECK (octet_length(wrapped_payload) = 1168),
  -- PUBLIC digests the §6.2 wrap AAD / AEAD bound. NOT key material: knowing them
  -- does not help unwrap without the gate private key. The reveal path needs them
  -- to re-derive the wrap AAD (plugin_version_digest, commit_context_digest_N) and
  -- to AEAD-decrypt the payload (commit_context_digest_0).
  plugin_version_digest BYTEA NOT NULL CHECK (octet_length(plugin_version_digest) = 32),
  commit_context_digest_n BYTEA NOT NULL CHECK (octet_length(commit_context_digest_n) = 32),
  commit_context_digest_0 BYTEA NOT NULL CHECK (octet_length(commit_context_digest_0) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (h_commit, stanza_index)
);

CREATE INDEX IF NOT EXISTS dek_share_records_h_commit_idx
  ON dek_share_records (h_commit);
