import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { deepStringIncludes, makeCiFailure } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-02")!; // verbatim spec anchor

export function checkCi02(pda: SubmittedPda): DualFormValidationFailure | null {
  const leaksSigmaAsKeyMaterial = deepStringIncludes(pda, [
    /sigma.*(dek|hkdf|ikm|key material|stored secret|confidential log)/i,
    /(dek|hkdf|ikm|key material).*sigma/i,
  ]);
  if (!leaksSigmaAsKeyMaterial) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "sigma_as_authorization",
    code: "SIGMA_TREATED_AS_KEY_MATERIAL",
    source_field_path: "$",
    failed_predicate: "sigma values authorize share admission and are not DEK/HKDF material",
    sanitized_value_class: "sigma_key_material_reference",
    cross_references: "S2-1 §6.3 Shamir reconstruction; S2-4 §4.3 CI-02",
    why_failed:
      "This configuration treats gate signatures as key material, but in V2 they only authorize share admission.",
    partner_action_text: "Remove sigma-as-key-material handling and keep sigma values out of stored secrets and logs.",
  });
}
