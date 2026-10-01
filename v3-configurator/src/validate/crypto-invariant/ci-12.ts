import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { deepStringIncludes, makeCiFailure, recordValue } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-12")!; // verbatim spec anchor

export function checkCi12(pda: SubmittedPda): DualFormValidationFailure | null {
  const shredCondition = recordValue(pda["shred_condition"]);
  const guardrailPresent =
    shredCondition?.["mandatory_guardrail_present"] === true ||
    deepStringIncludes(shredCondition, [/NOT post_challenge_reveal_in_progress/i]);
  if (guardrailPresent) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "mandatory_shred_guardrail",
    code: "SHRED_GUARDRAIL_MISSING",
    source_field_path: "shred_condition",
    failed_predicate: "every shred condition includes NOT post_challenge_reveal_in_progress",
    sanitized_value_class: "missing_guardrail",
    cross_references: "S2-4 §3.3 Test 1.5; S2-4 §4.3 CI-12",
    why_failed:
      "This configuration would allow shred to race an authorized reveal; Cealis rejects shred paths after gate signing starts.",
    partner_action_text: "Add the mandatory NOT post_challenge_reveal_in_progress guardrail to the shred condition.",
    remediation: "adjust_pda_value",
    category: "(a) PDA+",
    governance_sub_class: 5,
  });
}
