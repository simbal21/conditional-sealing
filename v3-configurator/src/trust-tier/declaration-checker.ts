import { isTrustTier, type TrustTier } from "./taxonomy.js";

export interface TrustTierDeclarationCheck {
  readonly ok: boolean;
  readonly declared_tier: TrustTier | null;
  readonly reason: string | null;
}

export function checkTrustTierDeclaration(
  value: string | undefined,
): TrustTierDeclarationCheck {
  if (value === undefined) {
    return {
      ok: false,
      declared_tier: null,
      reason: "trust_tier declaration missing",
    };
  }
  if (!isTrustTier(value)) {
    return {
      ok: false,
      declared_tier: null,
      reason: "trust_tier declaration is not A, B, or C",
    };
  }
  return { ok: true, declared_tier: value, reason: null };
}
