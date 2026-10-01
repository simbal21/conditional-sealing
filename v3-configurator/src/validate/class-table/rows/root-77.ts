// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_77_1: ClassTableRow = {
  "id": "77.1",
  "surface_name": "submitter_set_mode_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "submitter_sets_root",
  "rationale": "PDA picks oracle-self-only, relayer-set, or permitted submitter class from PDA+ allow-list."
};

export const ROW_77_2: ClassTableRow = {
  "id": "77.2",
  "surface_name": "submitter_set_parameters",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "submitter_sets_root",
  "rationale": "PDA sets submitter count, quorum, expiry, and per-set bounds inside PDA+ limits."
};
