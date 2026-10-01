import type { DualFormValidationFailure } from "../../errors/index.js";
import type { SubmittedPda as SyntaxSubmittedPda } from "../syntax/index.js";
import { checkCi01 } from "./ci-01.js";
import { checkCi02 } from "./ci-02.js";
import { checkCi03 } from "./ci-03.js";
import { checkCi04 } from "./ci-04.js";
import { checkCi05 } from "./ci-05.js";
import { checkCi06 } from "./ci-06.js";
import { checkCi07 } from "./ci-07.js";
import { checkCi08 } from "./ci-08.js";
import { checkCi09 } from "./ci-09.js";
import { checkCi10 } from "./ci-10.js";
import { checkCi11 } from "./ci-11.js";
import { checkCi12 } from "./ci-12.js";
import { checkCi13 } from "./ci-13.js";
import { checkCi14 } from "./ci-14.js";
import { checkCi15 } from "./ci-15.js";
import { checkCi16 } from "./ci-16.js";
import { checkCi17 } from "./ci-17.js";
import { checkCi18 } from "./ci-18.js";
import { checkCi19 } from "./ci-19.js";
import { checkCi20 } from "./ci-20.js";

export type SubmittedPda = SyntaxSubmittedPda;

export type CiCheck = (pda: SubmittedPda) => DualFormValidationFailure | null;

export const CI_CHECKS: readonly CiCheck[] = [
  checkCi01,
  checkCi02,
  checkCi03,
  checkCi04,
  checkCi05,
  checkCi06,
  checkCi07,
  checkCi08,
  checkCi09,
  checkCi10,
  checkCi11,
  checkCi12,
  checkCi13,
  checkCi14,
  checkCi15,
  checkCi16,
  checkCi17,
  checkCi18,
  checkCi19,
  checkCi20,
] as const;

export function runStage2(submittedPda: SubmittedPda): DualFormValidationFailure[] {
  return CI_CHECKS.flatMap((check) => {
    const failure = check(submittedPda);
    return failure === null ? [] : [failure];
  });
}
