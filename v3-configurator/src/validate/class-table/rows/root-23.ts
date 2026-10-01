// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_23: ClassTableRow = {
  "id": "23",
  "surface_name": "shred_authority_allowed_modes",
  "test_exited_on": "2",
  "category": "(a) PDA+",
  "governance_sub_class": 4,
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "shred_authority_id via h_commit",
  "rationale": "PDA+ defines which of Subject, Joint, Operator, Timelock, Disabled are allowed per type."
};
