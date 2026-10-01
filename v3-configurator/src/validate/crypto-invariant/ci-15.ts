import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { makeCiFailure, numberValue, stringValue, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-15")!; // verbatim spec anchor

function phaseValue(pda: SubmittedPda): number | null {
  const numeric = numberValue(pda["g4_phase"] ?? pda["phase"]);
  if (numeric !== null) return numeric;
  const text = stringValue(pda["g4_phase"] ?? pda["phase"]);
  if (text === "Phase 1" || text === "Phase1") return 1;
  if (text === "Phase 2" || text === "Phase2") return 2;
  return null;
}

export function checkCi15(pda: SubmittedPda): DualFormValidationFailure | null {
  const phase = phaseValue(pda);
  const phaseOneSemanticOverclaim =
    phase === 1 &&
    (pda["phase_1_claim"] === "cryptographic_non_custody" ||
      pda["g4_phase_semantics"] === "phase1_partner_ready_guarantee");
  if ((phase === 1 || phase === 2) && !phaseOneSemanticOverclaim) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "g4_phase_semantics_fixed",
    code: phase === null ? "UNKNOWN_G4_PHASE" : "PHASE_1_SEMANTIC_OVERCLAIM",
    source_field_path: "g4_phase",
    failed_predicate: "G4 phase id is known and Phase 1 is not represented as cryptographic non-custody",
    sanitized_value_class: valueClass(pda["g4_phase"] ?? pda["phase"]),
    cross_references: "S2-3 G4 phase semantics; S2-4 §4.3 CI-15; S2-4 §4.5 CF-05 boundary",
    why_failed:
      "This G4 phase representation does not match V2 semantics; Phase 1 cannot be described as the cryptographic non-custody guarantee.",
    partner_action_text: "Use a known G4 phase id and reserve partner-ready legal-effect Phase 2 enforcement for Stage 4 CF-05.",
    remediation: "adjust_pda_value",
  });
}
