-- M5 Phase D auth, subject session, webhook, and audit persistence.
-- S2-5 §1.5, §5, §6, §7, §8, §15. V3 DB namespace only.

CREATE TABLE IF NOT EXISTS partners (
  partner_id uuid PRIMARY KEY,
  name text NOT NULL,
  api_key_id text NOT NULL UNIQUE,
  api_key_bcrypt text NOT NULL,
  signing_secret_encrypted text NOT NULL,
  scopes text[] NOT NULL,
  webhook_secret_encrypted text NOT NULL,
  webhook_url text,
  rate_limit_per_second integer NOT NULL DEFAULT 10,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS partners_api_key_id_idx ON partners (api_key_id);

CREATE TABLE IF NOT EXISTS user_accounts (
  user_id uuid PRIMARY KEY,
  subject_namespace text NOT NULL,
  passkey_credential_digest text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_sessions (
  session_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES user_accounts(user_id),
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS user_sessions_token_hash_idx ON user_sessions (token_hash);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  scope text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest text NOT NULL,
  response_status integer NOT NULL,
  response_body jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idempotency_keys_expires_at_idx ON idempotency_keys (expires_at);

CREATE TABLE IF NOT EXISTS onboarding_links (
  onboarding_link_id uuid PRIMARY KEY,
  partner_id uuid NOT NULL REFERENCES partners(partner_id),
  pda_id text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  label text,
  active boolean NOT NULL DEFAULT true,
  max_uses integer,
  used_count integer NOT NULL DEFAULT 0,
  redirect_url text,
  subject_hint_ref text,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS onboarding_links_partner_pda_idx ON onboarding_links (partner_id, pda_id);

CREATE TABLE IF NOT EXISTS partner_agreements (
  partner_agreement_id uuid PRIMARY KEY,
  partner_id uuid NOT NULL REFERENCES partners(partner_id),
  pda_id text NOT NULL,
  status text NOT NULL,
  effective_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS partner_agreements_partner_pda_idx ON partner_agreements (partner_id, pda_id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  delivery_id uuid PRIMARY KEY,
  event_id text NOT NULL,
  event_type text NOT NULL,
  partner_id uuid NOT NULL REFERENCES partners(partner_id),
  pda_id text NOT NULL,
  delivery_url_digest text NOT NULL,
  attempt_count integer NOT NULL DEFAULT 0,
  status_code integer,
  final_state text NOT NULL,
  dead_letter_ref text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS webhook_deliveries_event_idx ON webhook_deliveries (event_id);
CREATE INDEX IF NOT EXISTS webhook_deliveries_expires_at_idx ON webhook_deliveries (expires_at);

CREATE TABLE IF NOT EXISTS vault_audit_log (
  audit_id uuid PRIMARY KEY,
  actor_ref text NOT NULL,
  action text NOT NULL,
  h_commit text NOT NULL,
  partner_id uuid REFERENCES partners(partner_id),
  pda_id text,
  safe_refs jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  purge_after timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS vault_audit_log_h_commit_idx ON vault_audit_log (h_commit);

CREATE OR REPLACE FUNCTION vault_audit_log_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'vault_audit_log is append-only during retention window';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vault_audit_log_append_only_update ON vault_audit_log;
CREATE TRIGGER vault_audit_log_append_only_update
BEFORE UPDATE ON vault_audit_log
FOR EACH ROW EXECUTE FUNCTION vault_audit_log_no_update_delete();

DROP TRIGGER IF EXISTS vault_audit_log_append_only_delete ON vault_audit_log;
CREATE TRIGGER vault_audit_log_append_only_delete
BEFORE DELETE ON vault_audit_log
FOR EACH ROW EXECUTE FUNCTION vault_audit_log_no_update_delete();

CREATE TABLE IF NOT EXISTS push_subscriptions (
  subscription_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES user_accounts(user_id),
  endpoint_digest text NOT NULL,
  encrypted_subscription_ref text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
