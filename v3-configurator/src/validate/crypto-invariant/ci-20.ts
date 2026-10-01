import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { deepStringIncludes, makeCiFailure } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-20")!; // verbatim spec anchor

export function checkCi20(pda: SubmittedPda): DualFormValidationFailure | null {
  const disclosureAuthorizesReveal =
    pda["disclosure_registry_authorizes_reveal"] === true ||
    deepStringIncludes(pda["reveal_authorization_sources"], [/DisclosureRegistry/i, /sd[_ -]?proof[_ -]?success/i]);
  if (!disclosureAuthorizesReveal) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "disclosure_registry_not_reveal_authority",
    code: "DISCLOSURE_REGISTRY_AUTHORIZES_REVEAL",
    source_field_path: "reveal_authorization_sources",
    failed_predicate: "SD proof success is never an input to RevealAuthorized",
    sanitized_value_class: "sd_proof_as_reveal_authority",
    cross_references: "S2-2 §12 RevealAuthorized; S2-7 §12 SD isolation; S2-4 §4.3 CI-20",
    why_failed:
      "This configuration lets an SD proof authorize escrow reveal; disclosure success cannot unlock escrowed plaintext.",
    partner_action_text: "Remove DisclosureRegistry or SD proof success from reveal authorization inputs.",
  });
}
