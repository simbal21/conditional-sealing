-- Phase 4 (GAP-B) — content-addressed PDA-artifact store.
--
-- `partner_agreements` is only a POINTER table (partner_id, pda_id, status,
-- effective_at). The PDA CONFIG BODY (the configurator-emitted
-- PartnerReadableInspection + the submitted PDA record + retention policy) is
-- NOT on it. The `PdaArtifactLoader` (ingest provenance seam) needs the config
-- body to recompute the same HCommitArtifacts the route bound at ingest. This
-- table is the real artifact store the loader reads from.
--
-- The artifact body is the configurator's emitted JSON (inspection + submitted),
-- serialized with a Bytes32/Map-aware encoder so it round-trips back to the
-- runtime types the inspector consumes. Keyed by (partner_id, pda_id,
-- pda_version) — the same triple the active-agreement lookup uses. Content is
-- immutable per (partner_id, pda_id, pda_version): a new PDA version writes a new
-- row, never mutates an existing one (S2-4 content-addressed-template
-- immutability mirrored at the artifact layer).

CREATE TABLE IF NOT EXISTS pda_artifacts (
  partner_id TEXT NOT NULL,
  pda_id TEXT NOT NULL,
  pda_version TEXT NOT NULL,
  -- The configurator-emitted artifact body (inspection + submitted PDA record),
  -- serialized with the Bytes32/Map-aware codec (artifact-codec.ts).
  artifact_json JSONB NOT NULL,
  -- PDA-configured retention policy id (e.g. 'obligation_plus_3y'). Optional —
  -- nullable when the artifact does not name one.
  retention_policy_id TEXT,
  -- Live halt posture for the PDA (class-wide or per-PDA), if halted at emit.
  halted BOOLEAN,
  halt_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (partner_id, pda_id, pda_version)
);

CREATE INDEX IF NOT EXISTS pda_artifacts_partner_pda_idx
  ON pda_artifacts (partner_id, pda_id);
