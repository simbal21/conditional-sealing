// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_1: ClassTableRow = {
  "id": "1",
  "surface_name": "commit_version_0x0302",
  "test_exited_on": "1",
  "category": "(d) architectural fact",
  "governance_sub_class": "N/A",
  "default_table_index": "none",
  "cross_ref_to_pda_root_field": "commit_AAD.commit_version",
  "rationale": "A1+Shamir changes commit semantics; configurator cannot vary it per partner."
};
