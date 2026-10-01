import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { makeCiFailure, numberValue, recordValue, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-06")!; // verbatim spec anchor

export function checkCi06(pda: SubmittedPda): DualFormValidationFailure | null {
  const policy = recordValue(pda["conditional_recipients"]);
  const n = policy === null ? 0 : numberValue(policy["n"]);
  const k = policy === null ? 0 : numberValue(policy["k"]);
  const valid = n !== null && k !== null && ((n === 0 && k === 0) || (n > 0 && k >= 1 && k <= n));
  if (valid) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "conditional_recipient_threshold_bounds",
    code: "CONDITIONAL_THRESHOLD_DEGENERATE",
    source_field_path: "conditional_recipients",
    failed_predicate: "1 <= k <= n when n > 0; k = 0 only when n = 0",
    sanitized_value_class: valueClass(policy),
    cross_references: "S2-1 §6.3 conditional-recipient threshold; S2-4 §4.3 CI-06",
    why_failed:
      "This conditional-recipient policy has an impossible threshold, so it cannot reconstruct under the V2 share model.",
    partner_action_text: "Set conditional recipient n/k so k is at least 1 and no greater than n, or set both to zero.",
    remediation: "adjust_pda_value",
    category: "(a) PDA+",
    governance_sub_class: 4,
  });
}
