// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_5: ClassTableRow = {
  "id": "5",
  "surface_name": "shamir_conditional_threshold_k",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "commit_AAD.conditional_recipients_policy_digest",
  "rationale": "`k_conditional` varies by PDA but must satisfy PDA+ bounds."
};
