// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_64_1: ClassTableRow = {
  "id": "64.1",
  "surface_name": "composed_module_child_picks",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "condition spec hash",
  "rationale": "PDA picks child modules and operators from PDA+ allow-lists."
};

export const ROW_64_2: ClassTableRow = {
  "id": "64.2",
  "surface_name": "composed_module_tree_parameters",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "condition spec hash",
  "rationale": "PDA sets depth, child count, arity, thresholds, and ordering caps inside PDA+ bounds."
};
