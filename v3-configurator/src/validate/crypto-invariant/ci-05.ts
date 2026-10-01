import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { makeCiFailure, numberValue, recordValue, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-05")!; // verbatim spec anchor

export function checkCi05(pda: SubmittedPda): DualFormValidationFailure | null {
  const policy = recordValue(pda["conditional_recipients"]);
  const kConditional = policy === null ? 0 : (numberValue(policy["k"]) ?? 0);
  const expected = 3 + kConditional;
  const actual = numberValue(pda["global_shamir_threshold"]);
  if (actual === expected) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "global_threshold_3_plus_k_conditional",
    code: "GLOBAL_THRESHOLD_MISMATCH",
    source_field_path: "global_shamir_threshold",
    failed_predicate: "global Shamir threshold equals 3 + k_conditional",
    sanitized_value_class: valueClass(pda["global_shamir_threshold"]),
    cross_references: "S2-1 §6.3 Shamir threshold; S2-4 §4.3 CI-05",
    why_failed:
      "This deployment's global Shamir threshold does not match the fixed gates plus the conditional-recipient threshold.",
    partner_action_text: `Set global_shamir_threshold to ${String(expected)}.`,
    remediation: "adjust_pda_value",
    category: "(c) PDA parameter",
  });
}
