import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { isRecord, isZeroBytes32, makeCiFailure, recordValue, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-10")!; // verbatim spec anchor

function hasNonEscrowPolicy(value: unknown): boolean {
  if (typeof value === "string") return value !== "escrow_only";
  if (Array.isArray(value)) return value.some((entry) => hasNonEscrowPolicy(entry));
  if (isRecord(value)) return Object.values(value).some((entry) => hasNonEscrowPolicy(entry));
  return false;
}

export function checkCi10(pda: SubmittedPda): DualFormValidationFailure | null {
  const sdPlan = recordValue(pda["sd_plan"]);
  const sdEnabled = pda["sd_enabled"] === true;
  const sdRoot = pda["sdMerkleRoot"] ?? sdPlan?.["sdMerkleRoot"];
  const policies = pda["sd_field_policies"] ?? sdPlan?.["field_policies"];
  const nonEscrow = hasNonEscrowPolicy(policies);
  const missingRoot = sdEnabled && (typeof sdRoot !== "string" || isZeroBytes32(sdRoot));
  const sdOffButPolicyAssigned = !sdEnabled && nonEscrow;
  if (!missingRoot && !sdOffButPolicyAssigned) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "sd_merkle_root_binding",
    code: missingRoot ? "SD_ENABLED_ZERO_ROOT" : "SD_OFF_NON_ESCROW_POLICY",
    source_field_path: missingRoot ? "sdMerkleRoot" : "sd_field_policies",
    failed_predicate: "SD-enabled PDA has non-zero SD root; SD-off PDA uses escrow_only policies",
    sanitized_value_class: valueClass(missingRoot ? sdRoot : policies),
    cross_references: "S2-1 §4 commit_AAD.sdMerkleRoot; S2-7 §12; S2-4 §4.3 CI-10",
    why_failed:
      "This SD configuration is not bound correctly into commit_AAD: enabled SD needs a non-zero root, and disabled SD cannot assign cleartext or ZKP policies.",
    partner_action_text: "Either provide a non-zero sdMerkleRoot for SD output, or keep all SD policies escrow_only.",
    remediation: "adjust_pda_value",
  });
}
