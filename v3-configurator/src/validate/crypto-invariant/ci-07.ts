import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { arrayValue, isRecord, makeCiFailure } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-07")!; // verbatim spec anchor

function containsMode3(value: unknown): boolean {
  if (typeof value === "string") return value === "WALLET_EIP1271";
  if (Array.isArray(value)) return value.some((entry) => containsMode3(entry));
  if (isRecord(value)) {
    return Object.entries(value).some(([key, child]) => {
      return (key === "delivery_mode" || key === "delivery_modes") && containsMode3(child);
    });
  }
  return false;
}

export function checkCi07(pda: SubmittedPda): DualFormValidationFailure | null {
  const hasMode3 =
    containsMode3(pda["delivery_mode"]) ||
    containsMode3(pda["delivery_modes"]) ||
    arrayValue(pda["recipients"]).some((entry) => containsMode3(entry));
  if (!hasMode3) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "mode_3_reserved",
    code: "MODE_3_RESERVED",
    source_field_path: "delivery_mode",
    failed_predicate: "delivery_mode is not WALLET_EIP1271 for active V2 PDAs",
    sanitized_value_class: "enum_value_WALLET_EIP1271",
    cross_references: "S2-2 §11 Mode 3 rejection; S2-4 §4.3 CI-07",
    why_failed: "This recipient mode is reserved in V2 and cannot be selected.",
    partner_action_text: "Choose a non-reserved delivery mode for this V2 deployment.",
  });
}
