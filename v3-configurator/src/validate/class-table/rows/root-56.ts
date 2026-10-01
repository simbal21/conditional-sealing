// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_56_1: ClassTableRow = {
  "id": "56.1",
  "surface_name": "payment_obligation_template_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "use-case",
  "cross_ref_to_pda_root_field": "reveal condition spec / template_id",
  "rationale": "PDA picks an active content-addressed PaymentObligation template from the PDA+ allow-list."
};

export const ROW_56_2: ClassTableRow = {
  "id": "56.2",
  "surface_name": "payment_obligation_parameter_values",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "use-case",
  "cross_ref_to_pda_root_field": "reveal condition spec",
  "rationale": "Amount, deadline, grace, dispute, and obligation scalars are PDA parameters inside PDA+ bounds."
};
