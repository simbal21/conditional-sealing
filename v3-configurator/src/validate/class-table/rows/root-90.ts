// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_90_1: ClassTableRow = {
  "id": "90.1",
  "surface_name": "partner_legal_entity_jurisdiction_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "partner-fit",
  "cross_ref_to_pda_root_field": "off-chain PDA JSON / legal packet",
  "rationale": "Partner-fit/legal view: PDA picks incorporation or regulatory jurisdiction code from legal taxonomy."
};

export const ROW_90_2: ClassTableRow = {
  "id": "90.2",
  "surface_name": "partner_legal_entity_jurisdiction_set_parameters",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "partner-fit",
  "cross_ref_to_pda_root_field": "off-chain PDA JSON / legal packet",
  "rationale": "When legal packet allows multi-jurisdiction context, PDA sets set size, effective-date, and review-window bounds."
};
