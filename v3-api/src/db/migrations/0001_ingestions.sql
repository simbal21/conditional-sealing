-- M5 Phase B — ingestions + G4 attestation cache.
-- Source: docs/specs/ingestion-delivery-api-spec.md §§2.1-2.9, §11, §15.1.

CREATE TABLE IF NOT EXISTS ingestions (
  h_commit TEXT PRIMARY KEY CHECK (h_commit ~ '^0x[0-9a-fA-F]{64}$'),
  authorization_id TEXT NOT NULL CHECK (authorization_id ~ '^0x[0-9a-fA-F]{64}$'),
  pda_id TEXT NOT NULL,
  pda_version TEXT NOT NULL,
  partner_id TEXT NOT NULL,
  subject_commitment_v3 TEXT CHECK (subject_commitment_v3 IS NULL OR subject_commitment_v3 ~ '^0x[0-9a-fA-F]{64}$'),
  mode TEXT NOT NULL DEFAULT 'mode_a' CHECK (mode = 'mode_a'),
  g4_phase INTEGER NOT NULL CHECK (g4_phase IN (1, 2)),
  g3_choice TEXT NOT NULL CHECK (g3_choice IN ('dcipher', 'drand')),
  schema_digest TEXT NOT NULL CHECK (schema_digest ~ '^0x[0-9a-fA-F]{64}$'),
  payload_classification JSONB NOT NULL,
  vault_blob_ref TEXT NOT NULL,
  commit_block BIGINT,
  commit_block_hash TEXT CHECK (commit_block_hash IS NULL OR commit_block_hash ~ '^0x[0-9a-fA-F]{64}$'),
  commit_tx_hash TEXT,
  status TEXT NOT NULL CHECK (status IN ('committed', 'pending_chain_anchor', 'failed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  anchored_at TIMESTAMPTZ,
  retention_expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ingestions_partner_pda_idx ON ingestions (partner_id, pda_id);
CREATE INDEX IF NOT EXISTS ingestions_authorization_idx ON ingestions (authorization_id);
CREATE INDEX IF NOT EXISTS ingestions_status_idx ON ingestions (status);

CREATE TABLE IF NOT EXISTS g4_attestation_cache (
  cache_key TEXT PRIMARY KEY,
  pda_id TEXT NOT NULL,
  authorization_id_candidate TEXT NOT NULL CHECK (authorization_id_candidate ~ '^0x[0-9a-fA-F]{64}$'),
  preflight_context_digest TEXT NOT NULL CHECK (preflight_context_digest ~ '^0x[0-9a-fA-F]{64}$'),
  commit_block BIGINT NOT NULL,
  commit_block_hash TEXT NOT NULL CHECK (commit_block_hash ~ '^0x[0-9a-fA-F]{64}$'),
  attestation_digest TEXT NOT NULL CHECK (attestation_digest ~ '^0x[0-9a-fA-F]{64}$'),
  attestation_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS g4_attestation_cache_pda_auth_idx
  ON g4_attestation_cache (pda_id, authorization_id_candidate);

