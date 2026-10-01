import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { COMMIT_AAD_FIELD_NAMES } from "../../types/commit-aad.js";
import { arrayValue, makeCiFailure, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-14")!; // verbatim spec anchor

export function checkCi14(pda: SubmittedPda): DualFormValidationFailure | null {
  const fields = arrayValue(pda["commit_aad_fields"]);
  const valid =
    fields.length === COMMIT_AAD_FIELD_NAMES.length &&
    fields.every((entry, index) => entry === COMMIT_AAD_FIELD_NAMES[index]) &&
    fields.includes("sdMerkleRoot");
  if (valid) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "commit_aad_22_field_structure",
    code: "COMMIT_AAD_FIELD_SET_INVALID",
    source_field_path: "commit_aad_fields",
    failed_predicate: "commit_AAD fields match S2-1 §4 22-field structure including sdMerkleRoot",
    sanitized_value_class: valueClass(fields),
    cross_references: "S2-1 §4 commit_AAD; S2-7 §12 SD root binding; S2-4 §4.3 CI-14",
    why_failed:
      "This deployment changes the commit_AAD field set; commit_AAD must use the canonical 22-field structure including sdMerkleRoot.",
    partner_action_text: "Use the canonical S2-1 §4 commit_AAD field list.",
  });
}
