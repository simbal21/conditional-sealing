// 4 leaf predicate families + composed wrapper per §6 + §6.6.
//
// Claim type codes (§App.I.3 line 2224):
//   1 = range, 2 = equality, 3 = set, 4 = non_equality, 5 = composed
//
// §6.6 NORMATIVE — `composed` is a Claim WRAPPER over the 4 leaf families,
// NOT a fifth circuit. Phase C MUST NOT compile `circuits/composed.circom`;
// composed is implemented as a TS-side aggregator over leaf proofs PLUS
// (when warranted by partner profile) an outer Claim aggregation proof per
// §7.2 line 738.

export type LeafPredicateType = "range" | "equality" | "set_membership" | "non_equality";

/** §6.6 lines 671-673 caps — locked at Phase A; Phase B + C enforce. */
export const COMPOSED_CAPS = Object.freeze({
  MAX_DEPTH: 8,
  MAX_LEAVES: 32,
  MAX_FIELDS: 16,
});

export type ClaimTypeLabel = LeafPredicateType | "composed";

export const LEAF_PREDICATE_TYPES: ReadonlyArray<LeafPredicateType> = Object.freeze([
  "range",
  "equality",
  "set_membership",
  "non_equality",
]);

export const LEAF_PREDICATE_COUNT = 4 as const;
