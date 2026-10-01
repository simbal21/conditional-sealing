-- Phase C — reveal delivery tables.
-- S2-5 §3 event-driven reveal flow + §10.4 G4 refusal halt/advisory handling.

CREATE TABLE IF NOT EXISTS reveals (
  authorization_id text NOT NULL,
  h_commit text NOT NULL,
  recipient_ref text NOT NULL,
  bundle_digest text,
  bundle_storage_ref text,
  status text NOT NULL,
  g4_phase smallint NOT NULL CHECK (g4_phase IN (1, 2)),
  finalized_at timestamptz,
  challenge_window_expired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (authorization_id, recipient_ref)
);

CREATE INDEX IF NOT EXISTS reveals_h_commit_idx ON reveals (h_commit);
CREATE INDEX IF NOT EXISTS reveals_status_idx ON reveals (status);

CREATE TABLE IF NOT EXISTS event_cursors (
  chain_id integer NOT NULL,
  contract_address text NOT NULL,
  event_name text NOT NULL,
  last_processed_block bigint NOT NULL,
  last_processed_log_index integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, contract_address, event_name)
);

CREATE TABLE IF NOT EXISTS g4_refusals (
  refusal_id text PRIMARY KEY,
  authorization_id text NOT NULL,
  h_commit text NOT NULL,
  partner_id uuid NOT NULL,
  pda_id uuid NOT NULL,
  reason_code smallint NOT NULL CHECK (reason_code BETWEEN 1 AND 10),
  reason_code_hex text NOT NULL,
  reason_label text NOT NULL,
  reason_visibility text NOT NULL CHECK (reason_visibility IN ('encrypted', 'plaintext')),
  encrypted_reason_ref text,
  blocking boolean NOT NULL,
  refused_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT g4_refusals_encrypted_reason_required
    CHECK (
      (reason_visibility = 'encrypted' AND encrypted_reason_ref IS NOT NULL)
      OR (reason_visibility = 'plaintext')
    )
);

CREATE INDEX IF NOT EXISTS g4_refusals_authorization_idx ON g4_refusals (authorization_id);
CREATE INDEX IF NOT EXISTS g4_refusals_h_commit_idx ON g4_refusals (h_commit);
