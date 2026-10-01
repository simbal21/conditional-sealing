// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_67: ClassTableRow = {
  "id": "67",
  "surface_name": "evidence_retention_bounds",
  "test_exited_on": "2",
  "category": "(a) PDA+",
  "governance_sub_class": 4,
  "default_table_index": "use-case",
  "cross_ref_to_pda_root_field": "retention + shred condition",
  "rationale": "Evidence PDAs require bounded retention and cannot silently loosen shred."
};
