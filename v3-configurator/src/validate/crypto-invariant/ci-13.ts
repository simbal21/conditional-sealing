import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { PDA_ROOT_FIELD_NAMES, PDA_ROOT_FIELD_COUNT } from "../../types/pda-root.js";
import { PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE } from "../../m2-imports.js";
import { arrayValue, isRecord, makeCiFailure, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-13")!; // verbatim spec anchor

function sameOrder(actual: readonly unknown[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((entry, index) => entry === expected[index]);
}

export function checkCi13(pda: SubmittedPda): DualFormValidationFailure | null {
  const fields = arrayValue(pda["pda_root_fields"]);
  const rootObject = isRecord(pda["pda_root"]) ? pda["pda_root"] : null;
  const objectKeys = rootObject === null ? [] : Object.keys(rootObject);
  const extraFields = arrayValue(pda["pda_root_extra_fields"]);
  const fieldOrderValid =
    sameOrder(fields, PDA_ROOT_FIELD_NAMES) ||
    (fields.length === 0 && objectKeys.length > 0 && sameOrder(objectKeys, PDA_ROOT_FIELD_NAMES));
  const m2CountValid = PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE.length === PDA_ROOT_FIELD_COUNT;
  if (fieldOrderValid && extraFields.length === 0 && m2CountValid) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "pda_root_29_field_order",
    code: "PDA_ROOT_FIELD_ORDER_INVALID",
    source_field_path: "pda_root_fields",
    failed_predicate: "pda_root fields match S2-1 §3.3 29-field order and no app-specific crypto fields exist",
    sanitized_value_class: valueClass(fields.length > 0 ? fields : pda["pda_root"]),
    cross_references: "S2-1 §3.3; S2-2 App. A PdaRootFields; S2-4 §4.3 CI-13",
    why_failed:
      "This deployment changes the pda_root preimage shape; the root must use the canonical 29-field order.",
    partner_action_text: "Use the canonical S2-1 §3.3 pda_root field list without extra cryptographic fields.",
  });
}
