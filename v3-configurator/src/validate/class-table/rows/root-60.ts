// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_60_1: ClassTableRow = {
  "id": "60.1",
  "surface_name": "oracle_attestation_reference_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "oracle root, DSL version, spec hash",
  "rationale": "PDA picks oracle ref, schema, DSL version, and claim template from active PDA+ registries."
};

export const ROW_60_2: ClassTableRow = {
  "id": "60.2",
  "surface_name": "oracle_attestation_claim_parameters",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "condition spec hash",
  "rationale": "Thresholds, expiry, replay, confidence, freshness, and claim scalar values stay inside PDA+ bounds."
};
