import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { arrayValue, makeCiFailure, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-04")!; // verbatim spec anchor

const REQUIRED_FIXED_GATES = ["Lit V3", "G3", "G4"] as const;

export function checkCi04(pda: SubmittedPda): DualFormValidationFailure | null {
  const gates = arrayValue(pda["fixed_gates"]).map((entry) => String(entry));
  const missing = REQUIRED_FIXED_GATES.filter((gate) => !gates.includes(gate));
  if (missing.length === 0) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "fixed_gate_set_lit_g3_g4",
    code: "FIXED_GATE_REMOVED",
    source_field_path: "fixed_gates",
    failed_predicate: "fixed gate set contains Lit V3, G3, and G4",
    sanitized_value_class: valueClass(pda["fixed_gates"]),
    cross_references: "S2-1 §6.3 fixed base threshold; S2-4 §4.3 CI-04",
    why_failed:
      "This deployment removes at least one fixed custody gate, so the universal gate composition would no longer hold.",
    partner_action_text: `Include the fixed gates: ${REQUIRED_FIXED_GATES.join(", ")}.`,
  });
}
