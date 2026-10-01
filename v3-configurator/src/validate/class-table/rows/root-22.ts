// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_22: ClassTableRow = {
  "id": "22",
  "surface_name": "mandatory_shred_guardrail",
  "test_exited_on": "1.5",
  "category": "(a) PDA+",
  "governance_sub_class": 5,
  "default_table_index": "none",
  "cross_ref_to_pda_root_field": "shred_condition_spec_hash",
  "rationale": "Derived from universal tripwire; every shred condition must include `NOT post_challenge_reveal_in_progress`."
};
