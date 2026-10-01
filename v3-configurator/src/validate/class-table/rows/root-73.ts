// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_73: ClassTableRow = {
  "id": "73",
  "surface_name": "pause_authority_allowed_modes",
  "test_exited_on": "2",
  "category": "(a) PDA+",
  "governance_sub_class": 4,
  "default_table_index": "archetype",
  "cross_ref_to_pda_root_field": "pause_authority_id",
  "rationale": "Platform bounds pause to Partner, Joint, or None only; this is not the shred-authority enum."
};
