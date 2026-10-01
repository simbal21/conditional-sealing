-- Phase 3 Wave 2 — add the `manifest` + `bundle` jsonb columns to `reveals`.
--
-- The shipped 0002_reveals.sql created `reveals` WITHOUT these columns, but
-- src/db/schema-extensions/reveals.ts declares them (manifest jsonb, bundle
-- jsonb) and PostgresRevealArtifactRepository (src/bundle/postgres-reveal-
-- repository.ts) writes + reads both:
--   * `manifest` jsonb — the combiner manifest, written by putManifest into the
--     status-header row (recipient_ref = '__status__').
--   * `bundle`   jsonb — dual-purpose: the authorization-level status payload on
--     the status-header row, and the assembled RevealArtifactBundle on each
--     per-recipient row.
--
-- Additive, idempotent (ADD COLUMN IF NOT EXISTS), so re-running is a no-op and
-- the shipped 0002 stays untouched. No backfill needed — existing rows (if any)
-- get NULL, which the repository's parseJson() helper already tolerates.
--
-- V3 DB namespace only (cealis_v3_dev). No FK across to V1 cealis_dev.

ALTER TABLE reveals ADD COLUMN IF NOT EXISTS manifest jsonb;
ALTER TABLE reveals ADD COLUMN IF NOT EXISTS bundle jsonb;
