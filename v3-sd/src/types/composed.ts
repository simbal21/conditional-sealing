// Composed Claim wrapper bounded-tree type per §6.6 lines 665-680.
//
// `composed` is a Claim WRAPPER over the 4 leaf predicate families:
//   range, equality, set_membership, non_equality.
//
// Composition rules (§6.6 lines 669-680):
//   - bounded `AND`, `OR`, `NOT` only
//   - `AND` requires all child predicates true
//   - `OR` requires at least one child true (default OR circuit exposes
//     branch selector as a public input to keep constraints smaller)
//   - `NOT` may wrap ONLY equality, set membership, or bounded boolean
//     subclaims where the resulting semantics are unambiguous
//   - `NOT(range)` is represented as a configured OR of two ranges
//   - no unbounded loops, no floating point, no locale-sensitive string compare,
//     no external calls, no current time reads except public `as_of_timestamp`
//
// Caps:
//   - max depth 8
//   - max leaf predicates 32
//   - max fields per Claim 16

import type { LeafPredicateType } from "./predicates.js";
import type { Bytes32 } from "../tags/preimages.js";

import { COMPOSED_CAPS } from "./predicates.js";
export { COMPOSED_CAPS };

/**
 * Discriminated union representing a node in the composed-tree AST. Phase B
 * `sd-plan/build.ts` parses partner Claim config into this tree; Phase C
 * `prove/claim-aggregator.ts` walks the tree to produce leaf proofs + an
 * outer aggregation proof per §7.2 line 738.
 */
export type ComposedExprNode =
  | { readonly kind: "and"; readonly children: ReadonlyArray<ComposedExprNode> }
  | { readonly kind: "or"; readonly children: ReadonlyArray<ComposedExprNode> }
  | { readonly kind: "not"; readonly child: ComposedExprNode }
  | {
      readonly kind: "leaf";
      readonly predicate: LeafPredicateType;
      readonly field_id: Bytes32;
      /** Public predicate params from §6 — bounds for range, expected_value for equality, etc. */
      readonly params: ReadonlyArray<string>;
    };

/** AST cap-enforcement signature; Phase B body asserts and throws SdError on cap violation. */
export interface ComposedCapEnforcer {
  (node: ComposedExprNode): { readonly depth: number; readonly leaf_count: number; readonly field_count: number };
}
