// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_8: ClassTableRow = {
  "id": "8",
  "surface_name": "sd_failure_does_not_block_escrow",
  "test_exited_on": "1",
  "category": "(d) architectural fact",
  "governance_sub_class": "N/A",
  "default_table_index": "none",
  "cross_ref_to_pda_root_field": "sdMerkleRoot / S2-7 §12",
  "rationale": "SD is parallel; escrow commit cannot depend on SD success."
};
