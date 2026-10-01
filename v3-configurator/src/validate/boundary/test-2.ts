import type { BoundaryClassification, Surface } from "./types.js";
import type { BoundaryContext } from "./test-1.js";

const TEST_2_SURFACES = new Set<string>([
  "schema_library_membership",
  "schema_level_sd_availability",
  "fsm_template_library",
  "oracle_registry_admissibility",
  "oracle_schema_registry_admissibility",
  "dsl_version_registry_admissibility",
  "plugin_hash_registry_admissibility",
  "qtsp_registry_admissibility",
  "g4_authority_registry_admissibility",
  "retention_min_max_bounds",
  "allowed_shred_authority_modes_per_archetype",
  "ingestion_mode_availability",
  "cross_field_rules",
  "refusal_reason_encrypted_defaults",
  "art_9_basis_enum",
  "subject_authenticator_guardrail",
  "trust_tier_to_oracle_tier_consistency",
  "default_tables",
  "governance_cadence",
] as const);

export function runTest2(surface: Surface, context: BoundaryContext): BoundaryClassification | null {
  if (!TEST_2_SURFACES.has(surface) && context.cross_pda_class_invariant !== true) return null;
  return {
    test_exited_on: "2",
    category: "(a) PDA+",
    rationale:
      context.rationale ??
      `${surface} must be uniform across partners or governs the platform-wide admissible value set.`,
    derivation_pointer: null,
  };
}
