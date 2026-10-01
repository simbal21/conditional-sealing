import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { deepStringIncludes, makeCiFailure, stringValue, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-03")!; // verbatim spec anchor

export function checkCi03(pda: SubmittedPda): DualFormValidationFailure | null {
  const lifecycle = stringValue(pda["dek_lifecycle"]);
  const wrapsFullDek = pda["wraps_full_dek_to_single_gate"] === true;
  const templateLeaksFullDek = deepStringIncludes(pda["template"], [/full[_ -]?dek.*single[_ -]?gate/i]);
  if ((lifecycle === null || lifecycle === "A1_SHAMIR") && !wrapsFullDek && !templateLeaksFullDek) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "a1_shamir_lifecycle",
    code: "FULL_DEK_SINGLE_GATE_WRAP",
    source_field_path: lifecycle === null ? "template" : "dek_lifecycle",
    failed_predicate: "templates wrap one Shamir share per stanza, never full DEK to one gate",
    sanitized_value_class: valueClass(lifecycle ?? pda["template"]),
    cross_references: "S2-1 §6.3 Shamir reconstruction; S2-4 §4.3 CI-03",
    why_failed:
      "This configuration would let one gate recover the full DEK; Cealis requires Shamir shares across the gate set.",
    partner_action_text: "Use the A1_SHAMIR DEK lifecycle with one share per stanza.",
  });
}
