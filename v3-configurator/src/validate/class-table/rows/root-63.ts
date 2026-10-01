// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_63_1: ClassTableRow = {
  "id": "63.1",
  "surface_name": "consent_gate_authority_set_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "condition spec hash",
  "rationale": "PDA picks authority roles, addresses, or set root from allowed authority classes."
};

export const ROW_63_2: ClassTableRow = {
  "id": "63.2",
  "surface_name": "consent_gate_threshold_value",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "condition spec hash",
  "rationale": "PDA sets k-of-n threshold, quorum, and cardinality inside bounds; ConsentGate cannot alter reveal content."
};
