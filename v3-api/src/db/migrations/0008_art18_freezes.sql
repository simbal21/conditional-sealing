-- Phase 3 Wave 2 — per-subject Art.18 GDPR reveal-freeze table.
--
-- Backs PostgresArt18FreezeStore (src/reveal/live-ports/art18-port.ts), the live
-- per-subject Art.18 (right to restriction of processing) freeze the reveal-
-- coordinator reads at delivery time (fail-closed, no cache). No prior migration
-- created this table — the port's doc comment mis-attributed it to "0006", but
-- 0006 is dek_share_records. This migration adds it.
--
-- COLUMN SHAPE (must match PostgresArt18FreezeStore.getActiveFreeze EXACTLY):
--   getActiveFreeze SELECTs `subject_commitment, freeze_expires_at`
--   WHERE `subject_commitment = $1 AND lifted_at IS NULL LIMIT 1`.
--   The OPERATOR write path (T0.x / freeze-set) populates freeze_set_at,
--   freeze_expires_at, operator_ref, reason_ref. lifted_at is set on manual lift.
--
-- AUTO-EXPIRY (Decision D13, 90-day ceiling): every freeze carries
--   freeze_expires_at = freeze_set_at + 90d (OPERATOR may set sooner). The port
--   applies the expiry at READ time; the CHECK below enforces the 90-day ceiling
--   at WRITE time so a row can never outlive the legal max even if a sweeper
--   never runs. `<=` (not `<`) so an exactly-90-day freeze is admissible.
--
-- GDPR / legal (internal legal-constraints rules, not exported):
--   Per-subject (Art.18 is per-subject), so PK = subject_commitment. NO PII at
--   rest — subject_commitment is a commitment hash, reason_ref an opaque pointer.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS). V3 DB namespace only (cealis_v3_dev);
-- no FK across to V1 cealis_dev.

-- Column shape is byte-for-byte the scratch table the art18-port test
-- self-provisions (tests/reveal/live-ports/art18-port.test.ts:158): the test
-- INSERTs WITHOUT freeze_set_at, relying on `DEFAULT now()`, so this migration
-- MUST keep that default or the test's CREATE-TABLE-IF-NOT-EXISTS no-ops onto a
-- column the test cannot satisfy.
CREATE TABLE IF NOT EXISTS art18_freezes (
  -- Per-subject (Art.18 right to restriction is per-subject). Commitment hash,
  -- never PII. One active freeze per subject — PK enforces it.
  subject_commitment text PRIMARY KEY,
  -- When the OPERATOR set the freeze. DEFAULT now() so a write that omits it
  -- (the OPERATOR set-now path) lands at insert time.
  freeze_set_at      timestamptz NOT NULL DEFAULT now(),
  -- When the freeze auto-lifts (set_at + 90d, OPERATOR may set sooner).
  freeze_expires_at  timestamptz NOT NULL,
  -- Who set the freeze (OPERATOR_ROLE ref). Opaque, no PII.
  operator_ref       text NOT NULL,
  -- Opaque reason pointer; NO PII at rest.
  reason_ref         text,
  -- Non-null = manually lifted before auto-expiry. getActiveFreeze filters on
  -- `lifted_at IS NULL`.
  lifted_at          timestamptz,
  -- Decision D13: 90-day ceiling, enforced at write time. A small slack over the
  -- exact 90d admits the "set freeze for the full 90 days" path where
  -- freeze_expires_at = now()+90d is computed a hair BEFORE the DEFAULT now()
  -- that fills freeze_set_at (two distinct now() evaluations); without the slack
  -- that legitimate max-length freeze would fail the CHECK by microseconds. The
  -- read-time port (art18-port.ts) is the load-bearing expiry; this CHECK is the
  -- write-time backstop against a freeze that exceeds the legal ceiling.
  CONSTRAINT art18_freezes_90day_ceiling
    CHECK (freeze_expires_at <= freeze_set_at + interval '90 days' + interval '1 minute')
);
