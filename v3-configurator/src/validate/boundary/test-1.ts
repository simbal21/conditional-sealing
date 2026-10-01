import type { BoundaryClassification, Surface } from "./types.js";

const TEST_1_SURFACES = new Set<string>([
  "sigma_as_authorization",
  "commit_version_0x0302",
  "fixed_gate_set_lit_g3_g4",
  "shamir_fixed_threshold_base_3",
  "mode_3_reserved",
  "sd_failure_does_not_block_escrow",
  "two_pipelines_never_cross",
  "no_release_path_bypasses_chain_verified_condition",
  "shamir_single_share_leak_not_dek_leak",
] as const);

export interface BoundaryContext {
  readonly cryptographic_invariant?: boolean;
  readonly invariant_derived_from?: string;
  readonly cross_pda_class_invariant?: boolean;
  readonly value_kind?: "discrete" | "continuous";
  readonly rationale?: string;
}

export function asBoundaryContext(context: unknown): BoundaryContext {
  if (typeof context !== "object" || context === null || Array.isArray(context)) return {};
  return context as BoundaryContext;
}

export function runTest1(surface: Surface, context: BoundaryContext): BoundaryClassification | null {
  if (!TEST_1_SURFACES.has(surface) && context.cryptographic_invariant !== true) return null;
  return {
    test_exited_on: "1",
    category: "(d) architectural fact",
    rationale:
      context.rationale ??
      `${surface} participates in a cryptographic invariant or commit-version-coordinated primitive, so it is not configurable through PDA+.`,
    derivation_pointer: null,
  };
}
