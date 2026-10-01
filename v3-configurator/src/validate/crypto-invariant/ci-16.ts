import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { makeCiFailure, numberValue, stringValue, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-16")!; // verbatim spec anchor

export function checkCi16(pda: SubmittedPda): DualFormValidationFailure | null {
  const phase = numberValue(pda["g4_phase"] ?? pda["phase"]);
  if (phase !== 2) return null;
  const lit = stringValue(pda["lit_vendor_family"]);
  const g4 = stringValue(pda["g4_vendor_family"]);
  const invalid = lit === null || g4 === null || lit === "ambiguous" || g4 === "ambiguous" || lit === g4;
  if (!invalid) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "cross_vendor_tee_disjointness",
    code: "TEE_VENDOR_FAMILY_NOT_DISJOINT",
    source_field_path: "lit_vendor_family",
    failed_predicate: "Phase 2 Lit and G4 vendor families are known and disjoint",
    sanitized_value_class: valueClass({ lit, g4 }),
    cross_references: "S2-3 §2.4 cross-vendor TEE disjointness; S2-4 §4.3 CI-16",
    why_failed:
      "This Phase 2 configuration does not prove Lit and G4 run on disjoint TEE vendor families; ambiguous or identical families fail closed.",
    partner_action_text: "Choose a Lit/G4 vendor-family pair that is classified and disjoint.",
    remediation: "adjust_pda_value",
    category: "(a) PDA+",
    governance_sub_class: 5,
  });
}
