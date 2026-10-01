// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_79_1: ClassTableRow = {
  "id": "79.1",
  "surface_name": "applicable_jurisdiction_code_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "applicable_jurisdiction",
  "rationale": "PDA picks scalar jurisdiction code or each set member from PDA+ jurisdiction taxonomy."
};

export const ROW_79_2: ClassTableRow = {
  "id": "79.2",
  "surface_name": "applicable_jurisdiction_set_parameters",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "applicable_jurisdiction",
  "rationale": "When set-valued shape is enabled, PDA sets max size, required coverage, and min-count bounds."
};
