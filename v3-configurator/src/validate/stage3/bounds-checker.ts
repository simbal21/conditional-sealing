// S2-4 §4.4 — Stage 3 min/max bounds check for category (c).

import type { DualFormValidationFailure } from "../../errors/index.js";
import type { ClassTableRow } from "../../types/class-table.js";
import {
  createStage3Failure,
  readStage3Policy,
  stage3ValueClass,
  type Stage3PolicyMap,
  type Stage3Value,
} from "./allow-list-checker.js";

export interface NumericBounds {
  readonly min: number | bigint;
  readonly max: number | bigint;
  readonly inclusiveMin?: boolean;
  readonly inclusiveMax?: boolean;
}

export type BoundsPolicyMap = Stage3PolicyMap<NumericBounds>;

export interface BoundsCheckInput {
  readonly row: ClassTableRow;
  readonly value: Stage3Value | undefined;
  readonly bounds: BoundsPolicyMap | undefined;
  readonly sourceFieldPath?: string;
}

export function checkBounds(input: BoundsCheckInput): DualFormValidationFailure | null {
  const { row, value, bounds } = input;
  if (row.category !== "(c) PDA parameter") return null;

  const activeBounds = readStage3Policy(bounds, row);
  if (activeBounds === undefined) {
    return createStage3Failure({
      row,
      code: "BOUNDS_MISSING",
      failedPredicate: "PDA+ min/max bounds are missing for category (c) surface",
      sanitizedValueClass: stage3ValueClass(value),
      sourceFieldPath: input.sourceFieldPath,
      partnerAction: "request_pda_plus_change",
      remediationText: "Add or activate PDA+ min/max bounds before this parameter surface can be emitted.",
    });
  }

  if (!isNumericValue(value)) {
    return createStage3Failure({
      row,
      code: "BOUNDS_VALUE_NOT_NUMERIC",
      failedPredicate: "submitted value is not a numeric Stage 3 parameter",
      sanitizedValueClass: stage3ValueClass(value),
      sourceFieldPath: input.sourceFieldPath,
      partnerAction: "choose_different_allowed_option",
      remediationText: "Supply a numeric PDA value inside the active PDA+ bounds.",
    });
  }

  const belowMin =
    activeBounds.inclusiveMin === false
      ? compareNumeric(value, activeBounds.min) <= 0
      : compareNumeric(value, activeBounds.min) < 0;
  const aboveMax =
    activeBounds.inclusiveMax === false
      ? compareNumeric(value, activeBounds.max) >= 0
      : compareNumeric(value, activeBounds.max) > 0;

  if (!belowMin && !aboveMax) return null;

  return createStage3Failure({
    row,
    code: "BOUNDS_VALUE_OUT_OF_RANGE",
    failedPredicate: "submitted numeric value sits outside the active PDA+ min/max bounds",
    sanitizedValueClass: stage3ValueClass(value),
    sourceFieldPath: input.sourceFieldPath,
    partnerAction: "choose_different_allowed_option",
    remediationText: "Choose a numeric value inside the effective PDA+ bounds for this deployment context.",
  });
}

function isNumericValue(value: Stage3Value | undefined): value is number | bigint {
  return typeof value === "number" || typeof value === "bigint";
}

function compareNumeric(left: number | bigint, right: number | bigint): number {
  if (typeof left === "bigint" && typeof right === "bigint") {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
  }
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  if (leftNumber < rightNumber) return -1;
  if (leftNumber > rightNumber) return 1;
  return 0;
}

