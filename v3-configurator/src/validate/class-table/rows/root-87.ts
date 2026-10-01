// Generated from docs/specs/configurator-pda-spec.md §5.2. Do not hand-edit row prose.
import type { ClassTableRow } from "../../../types/class-table.js";

export const ROW_87_1: ClassTableRow = {
  "id": "87.1",
  "surface_name": "per_pda_pricing_tier_pick",
  "test_exited_on": "3",
  "category": "(b) PDA pick",
  "governance_sub_class": "N/A",
  "default_table_index": "commercial",
  "cross_ref_to_pda_root_field": "off-chain PDA JSON; billing system",
  "rationale": "Commercial view: PDA picks a billing catalog tier; price tier is not a cryptographic invariant."
};

export const ROW_87_2: ClassTableRow = {
  "id": "87.2",
  "surface_name": "per_pda_pricing_amounts",
  "test_exited_on": "3",
  "category": "(c) PDA parameter",
  "governance_sub_class": "N/A",
  "default_table_index": "commercial",
  "cross_ref_to_pda_root_field": "off-chain PDA JSON; billing system",
  "rationale": "Commercial view: retainer, per-identity, per-obligation, per-reveal, percentage, cap, and floor values stay inside billing bounds."
};
