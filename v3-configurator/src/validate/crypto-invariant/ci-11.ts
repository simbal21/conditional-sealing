import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { deepStringIncludes, makeCiFailure } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-11")!; // verbatim spec anchor

export function checkCi11(pda: SubmittedPda): DualFormValidationFailure | null {
  const bypassesReveal =
    pda["bypass_on_chain_condition"] === true ||
    pda["delivery_before_reveal_authorized"] === true ||
    pda["plaintext_before_reveal_authorized"] === true ||
    deepStringIncludes(pda["template"], [/bypass.*RevealAuthorized/i, /plaintext.*before.*RevealAuthorized/i]);
  if (!bypassesReveal) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "no_release_path_bypasses_chain_condition",
    code: "RELEASE_BYPASSES_CHAIN_CONDITION",
    source_field_path: "template",
    failed_predicate: "no delivery, fallback, resolver, or override path produces plaintext before RevealAuthorized",
    sanitized_value_class: "bypass_release_path",
    cross_references: "S2-2 §12 RevealAuthorized; S2-4 §4.3 CI-11",
    why_failed:
      "This template can produce plaintext before the on-chain condition authorizes reveal; Cealis rejects any release path that bypasses the chain-verified condition.",
    partner_action_text: "Remove pre-authorization plaintext delivery, fallback, resolver, or override paths.",
  });
}
