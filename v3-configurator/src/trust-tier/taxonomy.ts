import type { TrustTier } from "../validate/cross-field/types.js";

export { type TrustTier };

export const TRUST_TIER_LABELS: Record<TrustTier, string> = {
  A: "chain-native facts",
  B: "commodity oracle",
  C: "bespoke oracle",
} as const;

export const TRUST_TIER_RANK: Record<TrustTier, number> = {
  A: 0,
  B: 1,
  C: 2,
} as const;

export function isTrustTier(value: string): value is TrustTier {
  return value === "A" || value === "B" || value === "C";
}

export function isOracleTierAllowedForDeclaration(
  declared_tier: TrustTier,
  oracle_tier: TrustTier,
): boolean {
  return TRUST_TIER_RANK[oracle_tier] <= TRUST_TIER_RANK[declared_tier];
}
