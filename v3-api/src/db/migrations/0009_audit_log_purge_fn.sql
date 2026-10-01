-- 0009 — vault_audit_log retention purge function.
--
-- Companion to the 0003 append-only trigger
-- (`vault_audit_log_append_only_update` / `..._append_only_delete`), which
-- raises on ANY raw UPDATE/DELETE. That trigger makes `vault_audit_log` an
-- append-only chain-of-custody store (legal: 12-month rolling retention,
-- "Legitimate Interest" — internal legal-constraints rules, not exported / D3).
--
-- The ONLY legal way to remove a row is this SECURITY-DEFINER function: it runs
-- as the migration/function owner (which owns the table + trigger), disables the
-- delete trigger for THIS table within its privileged context, deletes rows
-- whose `purge_after <= as_of`, then re-enables the trigger. No other code path
-- may DELETE from vault_audit_log. The production `RetentionWorker`'s
-- `PostgresAuditLogPurgePort` calls this function; before this migration the
-- function was absent and the worker's audit-log purge failed loud (Rule 19 —
-- never a silent fake-success). This closes that migration gap.
--
-- Signature MUST match PostgresAuditLogPurgePort.purgeExpired:
--   SELECT purge_old_audit_logs(<asOf timestamptz>, <retentionDays int>)
-- The 12-month window is encoded in each row's `purge_after` at write time;
-- `retention_days` is accepted for signature symmetry with a deployment that
-- recomputes the cutoff. Returns the count of rows purged.

CREATE OR REPLACE FUNCTION purge_old_audit_logs(as_of timestamptz, retention_days integer DEFAULT 365)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  purged_count integer;
BEGIN
  -- SECURITY DEFINER runs as the function owner; the append-only trigger fires
  -- per-row on DELETE, so we disable it for THIS table within the function's
  -- privileged context, purge, then re-enable. This is the single sanctioned
  -- bypass — no other code path may DELETE from vault_audit_log.
  ALTER TABLE vault_audit_log DISABLE TRIGGER vault_audit_log_append_only_delete;
  DELETE FROM vault_audit_log WHERE purge_after <= as_of;
  GET DIAGNOSTICS purged_count = ROW_COUNT;
  ALTER TABLE vault_audit_log ENABLE TRIGGER vault_audit_log_append_only_delete;
  RETURN purged_count;
END;
$$;
