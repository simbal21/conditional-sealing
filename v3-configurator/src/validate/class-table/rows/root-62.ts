// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_62_1: ClassTableRow = {
  "id": "62.1",
  "surface_name": "dead_man_switch_evidence_template_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "use-case",
  "cross_ref_to_pda_root_field": "condition spec hash",
  "rationale": "PDA picks a liveness, evidence, notification, and beneficiary template from PDA+ allowed templates."
};

export const ROW_62_2: ClassTableRow = {
  "id": "62.2",
  "surface_name": "dead_man_switch_evidence_parameters",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "use-case",
  "cross_ref_to_pda_root_field": "condition spec hash",
  "rationale": "Grace window, notification delay, beneficiary count, evidence expiry, and cadence-adjacent scalars stay inside bounds."
};
