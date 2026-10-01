// Access-structure profile types — V3 mirror of M1's
// `AccessStructureProfile` discriminated union with V3 SDK helpers.
//
// Per internal design record `4-gate-and-shamir-access-structure.md`
// + M1 `v3-crypto/src/crypto/shamir.ts` line 25, the
// supported profiles are:
//
//   FIXED_ONLY            — top-level only (Lit, G3, G4, optional Subject)
//   RECIPIENT_1_OF_1      — top-level + a single fixed recipient (no Shamir
//                           reconstruction on the recipient branch)
//   RECIPIENT_K_OF_N      — top-level + nested K-of-N over N conditional
//                           recipients
//
// The combiner imports M1's `combineDek(records, profile)` directly
// (re-exported via `src/m1-imports.ts`). This file provides V3-SDK-level
// helpers around the profile (decode from `commit_AAD`, profile
// enumeration for branch dispatch, etc.).

/**
 * Access-structure profile — V3 discriminated union. Same shape as
 * M1's `AccessStructureProfile` to allow direct pass-through to
 * `combineDek(records, profile)`.
 */
export type AccessStructureProfile =
  | { readonly kind: "FIXED_ONLY" }
  | { readonly kind: "RECIPIENT_1_OF_1" }
  | {
      readonly kind: "RECIPIENT_K_OF_N";
      readonly n_conditional: number;
      readonly k_conditional: number;
    };

/**
 * Validates an `AccessStructureProfile` payload — checks invariants
 * not enforced by the type system (range, k <= n, etc.).
 */
export function validateAccessStructureProfile(
  profile: AccessStructureProfile,
): void {
  if (profile.kind === "RECIPIENT_K_OF_N") {
    if (profile.n_conditional < 1) {
      throw new Error(
        `validateAccessStructureProfile: n_conditional must be >= 1, got ${profile.n_conditional}`,
      );
    }
    if (profile.k_conditional < 1) {
      throw new Error(
        `validateAccessStructureProfile: k_conditional must be >= 1, got ${profile.k_conditional}`,
      );
    }
    if (profile.k_conditional > profile.n_conditional) {
      throw new Error(
        `validateAccessStructureProfile: k_conditional (${profile.k_conditional}) > n_conditional (${profile.n_conditional})`,
      );
    }
    if (!Number.isInteger(profile.n_conditional) || !Number.isInteger(profile.k_conditional)) {
      throw new Error(
        `validateAccessStructureProfile: k/n must be integers`,
      );
    }
  }
}

/**
 * Returns true iff the profile requires the conditional-recipient
 * branch to participate. `RECIPIENT_1_OF_1` and `RECIPIENT_K_OF_N`
 * require it; `FIXED_ONLY` does not.
 */
export function requiresRecipientBranch(profile: AccessStructureProfile): boolean {
  return profile.kind !== "FIXED_ONLY";
}

/**
 * Returns the conditional-recipient threshold for the profile, or 0
 * if the profile does not use a conditional branch.
 *
 * - FIXED_ONLY:       0
 * - RECIPIENT_1_OF_1: 1
 * - RECIPIENT_K_OF_N: k_conditional
 */
export function conditionalThreshold(profile: AccessStructureProfile): number {
  switch (profile.kind) {
    case "FIXED_ONLY":
      return 0;
    case "RECIPIENT_1_OF_1":
      return 1;
    case "RECIPIENT_K_OF_N":
      return profile.k_conditional;
  }
}

/**
 * Returns the conditional-recipient cardinality for the profile, or 0
 * if the profile does not use a conditional branch.
 *
 * - FIXED_ONLY:       0
 * - RECIPIENT_1_OF_1: 1
 * - RECIPIENT_K_OF_N: n_conditional
 */
export function conditionalCardinality(profile: AccessStructureProfile): number {
  switch (profile.kind) {
    case "FIXED_ONLY":
      return 0;
    case "RECIPIENT_1_OF_1":
      return 1;
    case "RECIPIENT_K_OF_N":
      return profile.n_conditional;
  }
}
