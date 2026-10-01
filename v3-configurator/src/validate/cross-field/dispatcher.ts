import type { DualFormValidationFailure } from "../../errors/index.js";
import { validateCf01 } from "./cf-01.js";
import { validateCf02 } from "./cf-02.js";
import { validateCf03 } from "./cf-03.js";
import { validateCf04 } from "./cf-04.js";
import { validateCf05 } from "./cf-05.js";
import { validateCf06 } from "./cf-06.js";
import { validateCf07 } from "./cf-07.js";
import type {
  CrossFieldValidationContext,
  CrossFieldValidator,
} from "./types.js";

export const CROSS_FIELD_VALIDATORS: readonly CrossFieldValidator[] = [
  validateCf01,
  validateCf02,
  validateCf03,
  validateCf04,
  validateCf05,
  validateCf06,
  validateCf07,
] as const;

export function validateCrossFieldRules(
  context: CrossFieldValidationContext,
): readonly DualFormValidationFailure[] {
  const failures: DualFormValidationFailure[] = [];
  for (const validator of CROSS_FIELD_VALIDATORS) {
    failures.push(...validator(context));
  }
  return failures;
}
