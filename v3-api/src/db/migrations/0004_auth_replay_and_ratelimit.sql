-- R2b LBU mock→real swap: persist HMAC replay-nonce window + per-credential
-- rate-limit buckets. NEW entries in the V3 API canonical table catalog
-- (see `src/db/schema.ts:V3_API_TABLE_NAMES`). Operational tables — no PII,
-- no GDPR / Art. 18 / retention semantics. ADJ-2 STOP-gate not triggered.
--
-- Pair with `src/db/schema-extensions/auth.ts` (noncesAuth +
-- rateLimitBucketsAuth) and the Postgres store impls under `src/auth/`.

CREATE TABLE IF NOT EXISTS nonces (
  key_id text NOT NULL,
  nonce text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (key_id, nonce)
);

CREATE INDEX IF NOT EXISTS nonces_key_id_nonce_idx ON nonces (key_id, nonce);
CREATE INDEX IF NOT EXISTS nonces_expires_at_idx ON nonces (expires_at);

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key text PRIMARY KEY,
  count integer NOT NULL,
  reset_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rate_limit_buckets_reset_at_idx ON rate_limit_buckets (reset_at);
