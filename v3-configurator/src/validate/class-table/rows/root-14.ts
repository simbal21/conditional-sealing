// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_14: ClassTableRow = {
  "id": "14",
  "surface_name": "art_9_scoped_flag",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "art_9_scoped",
  "rationale": "PDA declares whether special-category processing applies; guardrail requires basis when true."
};

export const ROW_14_1: ClassTableRow = {
  "id": "14.1",
  "surface_name": "art_9_basis_id_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "art_9_basis_id",
  "rationale": "Required when `art_9_scoped = true`; PDA selects one taxonomy value from PDA+ and zeros the field when out of scope."
};
