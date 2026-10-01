// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_45: ClassTableRow = {
  "id": "45",
  "surface_name": "gate_recipient_pubkey_lifecycle",
  "test_exited_on": "1",
  "category": "(d) architectural fact",
  "governance_sub_class": "N/A",
  "default_table_index": "none",
  "cross_ref_to_pda_root_field": "S2-3 §2.5 / S2-2 §9.10A",
  "rationale": "Gate kind fixes ephemeral vs long-lived pubkey model; PDA cannot change it."
};
