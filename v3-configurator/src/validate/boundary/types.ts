// S2-4 §3 — Boundary-Decision Rule (NORMATIVE) signature contract.
//
// Phase A locks the function signature ONLY. Phase B implements the
// 3-test cascade + Test-1.5 body under `src/validate/boundary/cascade.ts`,
// `test-1.ts`, `test-1-5.ts`, `test-2.ts`, `test-3.ts`. Phase B MUST NOT
// touch this file (read-only contract).
//
// Cascade exit semantics per §3.6:
//   - apply tests in order; exit at first classification.
//   - each row records exactly ONE `test_exited_on` value.
//   - if a surface appears to pass two tests, decompose into two rows.
//   - no row may have "mixed" category.

import type { Category, TestExitedOn } from "../../types/categories.js";

/**
 * Configuration surface identifier (free-form snake_case stable id from
 * the class-table row, or a candidate identifier for a new surface
 * being evaluated against the cascade).
 */
export type Surface = string;

/**
 * Result of running the boundary-decision cascade on one surface.
 *
 * Per §3.6, `test_exited_on` is a single value (no mixed exits). The
 * `rationale` field is mandatory per §5.5 audit requirement (Phase B
 * implementation MUST supply prose).
 *
 * For Test 1.5 results, the `derivation_pointer` field is mandatory —
 * it names the underlying category (d) invariant from which the
 * category (a) PDA+ rule derives (e.g., universal tripwire → mandatory
 * shred guardrail per §3.3).
 */
export interface BoundaryClassification {
  /** Cascade exit point. */
  readonly test_exited_on: TestExitedOn;
  /** Category locked by the cascade exit point. */
  readonly category: Category;
  /** Substantive prose rationale per §5.5 (mandatory). */
  readonly rationale: string;
  /**
   * For Test-1.5 exits (category (a) with derivation pointer):
   * stable identifier of the underlying category (d) invariant.
   * Null for non-Test-1.5 exits.
   */
  readonly derivation_pointer: string | null;
}

/**
 * Boundary-decision cascade signature (Phase B implements body).
 *
 * @param surface Surface identifier to classify.
 * @param context Phase B implementations may consume additional context
 *   (e.g., reference to PDA+ libraries, current spec version). Phase A
 *   leaves this as `unknown` — Phase B narrows it.
 *
 * @returns BoundaryClassification per §3.6 single-exit semantics.
 *
 * Phase A foundation test `boundary-signature.test.ts` asserts:
 *   - function exists in the boundary module barrel;
 *   - returns a BoundaryClassification-shaped value;
 *   - for the spec examples in §3.2-§3.5, returns the expected exit
 *     point + category.
 */
export type ClassifySurfaceSignature = (
  surface: Surface,
  context?: unknown,
) => BoundaryClassification;

/**
 * Phase A placeholder — Phase B overrides with the working cascade.
 *
 * This default returns a category-(d) "not_classified" sentinel that
 * MUST never appear in production output; Phase B's `index.ts` shadows
 * this with the real implementation.
 */
export const classifySurface: ClassifySurfaceSignature = (
  surface: Surface,
  _context?: unknown,
): BoundaryClassification => {
  return {
    test_exited_on: "1",
    category: "(d) architectural fact",
    rationale: `Phase A placeholder for surface ${JSON.stringify(surface)} — Phase B implements cascade body.`,
    derivation_pointer: null,
  };
};
