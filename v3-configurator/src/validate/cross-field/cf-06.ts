import { CF_BY_ID } from "../../types/cf-codes.js";
import { checkOracleTierConsistency } from "../../trust-tier/oracle-tier-consistency.js";
import { createCfFailure } from "./failure.js";
import {
  getOracleRefs,
  getTrustTier,
  requiredCfDescriptor,
} from "./helpers.js";
import type { CrossFieldValidationContext } from "./types.js";

const CF_06 = CF_BY_ID.get("CF-06");

export function validateCf06(context: CrossFieldValidationContext) {
  const descriptor = requiredCfDescriptor(CF_06, "CF-06");
  const { pda } = context;
  const result = checkOracleTierConsistency({
    declared_tier: getTrustTier(pda),
    oracle_refs: getOracleRefs(pda),
    tier_c_acknowledgment_bound: pda.tier_c_acknowledgment_bound === true,
  });
  if (result.ok) return [];
  return result.reasons.map((reason) =>
    createCfFailure({
      descriptor,
      surface_name: "trust_tier",
      code: "ORACLE_TIER_INCONSISTENT_WITH_DECLARATION",
      failed_predicate: reason,
      source_field_path: "oracle_refs",
      sanitized_value_class: "oracle_tier_outside_declared_trust_tier",
      partner_friendly_field_label: "Trust tier and oracle set",
      why_failed:
        "The selected oracle set is below the trust tier claimed by this PDA.",
      partner_action_text:
        "Choose oracle refs that match the declared tier, or declare the PDA as Tier C with an explicit acknowledgment.",
    }),
  );
}
