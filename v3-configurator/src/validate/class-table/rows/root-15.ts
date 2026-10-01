// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_15: ClassTableRow = {
  "id": "15",
  "surface_name": "legal_effect_classification_rule",
  "test_exited_on": "2",
  "category": "(a) PDA+",
  "governance_sub_class": 4,
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "legal_effect_expected",
  "rationale": "PDA+ owns the rule that derives legal-effect posture and mandatory guardrails; partners cannot self-label around it."
};

export const ROW_15_1: ClassTableRow = {
  "id": "15.1",
  "surface_name": "legal_effect_expected_value",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "legal_effect_expected",
  "rationale": "Frozen per-PDA value set or derived by Cealis operator under the classification rule; partner inspection only, not partner-free-form."
};
