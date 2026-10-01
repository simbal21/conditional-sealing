import type { DualFormValidationFailure } from "../../errors/index.js";
import { checkBytes32Hex } from "./bytes32-hex.js";
import { checkCidParse } from "./cid-parse.js";
import { checkDurationSeconds } from "./duration-seconds.js";
import { checkEnumMapping } from "./enum-mapping.js";
import { checkJcsRoundTrip } from "./jcs-roundtrip.js";
import {
  checkRequiredFields,
  makeStage1Failure,
  type SubmittedPda,
  type SyntaxViolation,
} from "./required-fields.js";
import { checkSchemaMappingPath } from "./schema-mapping-path.js";
import { checkUnknownFields } from "./unknown-fields.js";

export type { SubmittedPda, SyntaxViolation } from "./required-fields.js";
export { checkRequiredFields } from "./required-fields.js";
export { checkUnknownFields } from "./unknown-fields.js";
export { checkEnumMapping } from "./enum-mapping.js";
export { checkBytes32Hex } from "./bytes32-hex.js";
export { checkCidParse } from "./cid-parse.js";
export { checkDurationSeconds } from "./duration-seconds.js";
export { checkJcsRoundTrip } from "./jcs-roundtrip.js";
export { checkSchemaMappingPath } from "./schema-mapping-path.js";

const STAGE_1_CHECKS: readonly ((pda: SubmittedPda) => readonly SyntaxViolation[])[] = [
  checkRequiredFields,
  checkUnknownFields,
  checkEnumMapping,
  checkBytes32Hex,
  checkCidParse,
  checkDurationSeconds,
  checkJcsRoundTrip,
  checkSchemaMappingPath,
] as const;

export function runStage1(submittedPda: SubmittedPda): DualFormValidationFailure[] {
  return STAGE_1_CHECKS.flatMap((check) =>
    check(submittedPda).map((violation) => makeStage1Failure(violation)),
  );
}
