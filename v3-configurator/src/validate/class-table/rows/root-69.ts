// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_69_1: ClassTableRow = {
  "id": "69.1",
  "surface_name": "testament_flow_template_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "use-case",
  "cross_ref_to_pda_root_field": "conditional policy + condition hash",
  "rationale": "PDA picks testament, vital-record, dead-man path, and role-tag template from PDA+ allowed templates."
};

export const ROW_69_2: ClassTableRow = {
  "id": "69.2",
  "surface_name": "testament_flow_parameters",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "use-case",
  "cross_ref_to_pda_root_field": "conditional policy + condition hash",
  "rationale": "PDA sets vital-record k-of-n, recipient count, TTL, update windows, and long-retention scalars inside bounds."
};
