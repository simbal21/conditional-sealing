import type { OracleRef, TrustTier } from "../validate/cross-field/types.js";
import { isOracleTierAllowedForDeclaration } from "./taxonomy.js";

export interface OracleTierConsistencyInput {
  readonly declared_tier: TrustTier;
  readonly oracle_refs: readonly OracleRef[];
  readonly tier_c_acknowledgment_bound?: boolean;
}

export interface OracleTierConsistencyResult {
  readonly ok: boolean;
  readonly reasons: readonly string[];
}

export function checkOracleTierConsistency(
  input: OracleTierConsistencyInput,
): OracleTierConsistencyResult {
  const reasons: string[] = [];
  for (const ref of input.oracle_refs) {
    if (input.declared_tier === "A" && ref.tier !== "A") {
      reasons.push(
        "Tier A PDA references Tier B or Tier C oracle on a relevant axis",
      );
      continue;
    }
    if (
      input.declared_tier === "A" &&
      ref.classified_as_chain_native === false
    ) {
      reasons.push(
        "Tier A PDA references an oracle ref not classified as chain-native",
      );
      continue;
    }
    if (!isOracleTierAllowedForDeclaration(input.declared_tier, ref.tier)) {
      reasons.push(
        "Tier B PDA references Tier C oracle without declaring the PDA as Tier C",
      );
    }
  }
  if (
    input.declared_tier === "C" &&
    input.tier_c_acknowledgment_bound !== true
  ) {
    reasons.push(
      "Tier C PDA requires explicit partner acknowledgment bound into the inspection surface",
    );
  }
  return { ok: reasons.length === 0, reasons };
}
