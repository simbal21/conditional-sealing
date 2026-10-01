import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { isRecord, makeCiFailure, recordValue } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-09")!; // verbatim spec anchor

function isModeB(value: unknown): boolean {
  return value === "ModeB" || value === "B" || value === 2;
}

function hasNonEscrowPolicy(value: unknown): boolean {
  if (typeof value === "string") return value !== "escrow_only";
  if (Array.isArray(value)) return value.some((entry) => hasNonEscrowPolicy(entry));
  if (isRecord(value)) return Object.values(value).some((entry) => hasNonEscrowPolicy(entry));
  return false;
}

export function checkCi09(pda: SubmittedPda): DualFormValidationFailure | null {
  const policies = pda["sd_field_policies"] ?? recordValue(pda["sd_plan"])?.["field_policies"];
  if (!isModeB(pda["ingestion_mode"]) || !hasNonEscrowPolicy(policies)) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "mode_b_sd_incompatibility",
    code: "MODE_B_NON_ESCROW_SD_POLICY",
    source_field_path: "sd_field_policies",
    failed_predicate: "Mode B SD mappings are all escrow_only",
    sanitized_value_class: "non_escrow_sd_policy",
    cross_references: "S2-7 §12 Mode B incompatibility; S2-4 §4.3 CI-09",
    why_failed:
      "This deployment uses device-side Mode B ingestion, so it cannot request cleartext or ZKP SD outputs.",
    partner_action_text: "Set every SD field policy to escrow_only, or switch to Mode A where TEE-side SD is available.",
    remediation: "adjust_pda_value",
  });
}
