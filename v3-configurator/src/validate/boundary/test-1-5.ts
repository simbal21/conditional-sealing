import type { BoundaryClassification, Surface } from "./types.js";
import type { BoundaryContext } from "./test-1.js";

const TEST_1_5_DERIVATIONS = new Map<string, string>([
  ["mandatory_shred_guardrail", "universal_tripwire"],
  ["not_post_challenge_reveal_in_progress_guardrail", "universal_tripwire"],
] as const);

export function runTest15(surface: Surface, context: BoundaryContext): BoundaryClassification | null {
  const derivation = TEST_1_5_DERIVATIONS.get(surface) ?? context.invariant_derived_from ?? null;
  if (derivation === null) return null;
  return {
    test_exited_on: "1.5",
    category: "(a) PDA+",
    rationale:
      context.rationale ??
      `${surface} is a PDA-layer validator derived from the category-(d) invariant ${derivation}.`,
    derivation_pointer: derivation,
  };
}
