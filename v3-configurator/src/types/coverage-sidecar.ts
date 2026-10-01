// S2-4 §5.4A — Coverage sidecar for CI consistency.
//
// "The table's rationale prose is audit context, not the source for
// machine coverage checks. Implementations MUST materialize the sidecar
// below as structured data keyed by row id."
//
// Phase A locks the SHAPE (7 views + 9 condition modules) AND the
// required row id list per view / module verbatim from §5.4A. Phase C
// materializes the sidecar instance and runs the consistency check.
//
// Foundation test `tests/foundation/coverage-sidecar-shape.test.ts`
// asserts the 7 view keys + 9 condition-module keys present and that
// every required row id parses to a valid RowId.

import type { RowId } from "./class-table.js";

/**
 * The 7 view names per Section 0 of the internal project constitution (View Register) +
 * S2-4 §5.4A.
 *
 * Spec uses display names like "Tamper-proof / integrity" and
 * "Selective Disclosure" — we collapse to TypeScript-safe keys per
 * SPEC-COMPLIANCE-GUARD §5:
 *   "Tamper-proof / integrity" → "TamperProof"
 *   "Selective Disclosure"      → "SelectiveDisclosure"
 *   "Use-case flex"             → "UseCaseFlex"
 *   "Partner-fit"               → "PartnerFit"
 *   (others stay verbatim)
 */
export interface ViewCoverage {
  readonly Enforcement: readonly RowId[];
  readonly TamperProof: readonly RowId[];
  readonly SelectiveDisclosure: readonly RowId[];
  readonly Commercial: readonly RowId[];
  readonly Legal: readonly RowId[];
  readonly UseCaseFlex: readonly RowId[];
  readonly PartnerFit: readonly RowId[];
}

/**
 * The 9 condition modules per S2-2 + S2-4 §5.4A.
 *
 * Display names use the canonical Solidity-style PascalCase from S2-2
 * (e.g., `PaymentObligation`, `DeadManSwitch`) — these are stable
 * identifiers consumed by the M2 contract surface.
 */
export interface ConditionModuleCoverage {
  readonly PaymentObligation: readonly RowId[];
  readonly TimeLock: readonly RowId[];
  readonly SubjectInitiated: readonly RowId[];
  readonly HeartbeatMissed: readonly RowId[];
  readonly OracleAttestation: readonly RowId[];
  readonly MultiPartySignal: readonly RowId[];
  readonly DeadManSwitch: readonly RowId[];
  readonly ConsentGate: readonly RowId[];
  readonly Composed: readonly RowId[];
}

/**
 * Full sidecar interface — Phase C materializes one instance keyed by
 * row id; consistency check (§5.4) walks both axes.
 */
export interface CoverageSidecar {
  readonly views: ViewCoverage;
  readonly conditionModules: ConditionModuleCoverage;
}

// ---------------------------------------------------------------------------
// Verbatim row-id lists from §5.4A — Phase C uses these as the spec-
// compliance anchor. Foundation test asserts every row id resolves.
// ---------------------------------------------------------------------------

/**
 * View-coverage required row ids — verbatim from §5.4A (lines 656-664).
 *
 * View | Required row ids
 * Enforcement | `3`, `22`, `56.1`, `56.2`, `61`, `70`
 * Tamper-proof / integrity | `67`, `68`, `91`
 * Selective Disclosure | `8`, `9`, `10`, `76`
 * Commercial | `87.1`, `87.2`, `88`
 * Legal | `13`, `14`, `14.1`, `15`, `15.1`, `18`, `19`, `33`, `34`
 * Use-case flex | `53`, `54`, `55`, `57`, `58`, `59`, `60.1`, `60.2`, `61`, `62.1`, `62.2`, `63.1`, `63.2`, `64.1`, `64.2`, `69.1`, `69.2`
 * Partner-fit | `89`, `90.1`, `90.2`, `91`
 */
export const REQUIRED_VIEW_ROW_IDS: ViewCoverage = {
  Enforcement: ["3", "22", "56.1", "56.2", "61", "70"] as const,
  TamperProof: ["67", "68", "91"] as const,
  SelectiveDisclosure: ["8", "9", "10", "76"] as const,
  Commercial: ["87.1", "87.2", "88"] as const,
  Legal: ["13", "14", "14.1", "15", "15.1", "18", "19", "33", "34"] as const,
  UseCaseFlex: [
    "53",
    "54",
    "55",
    "57",
    "58",
    "59",
    "60.1",
    "60.2",
    "61",
    "62.1",
    "62.2",
    "63.1",
    "63.2",
    "64.1",
    "64.2",
    "69.1",
    "69.2",
  ] as const,
  PartnerFit: ["89", "90.1", "90.2", "91"] as const,
} as const;

/**
 * Condition-module coverage required row ids — verbatim from §5.4A
 * (lines 668-678).
 *
 * Condition module | Required row ids
 * PaymentObligation | `56.1`, `56.2`
 * TimeLock | `57`
 * SubjectInitiated | `58`
 * HeartbeatMissed | `59`, `62.1`, `62.2`
 * OracleAttestation | `60.1`, `60.2`
 * MultiPartySignal | `61`, `70`, `69.2`
 * DeadManSwitch | `62.1`, `62.2`, `69.1`
 * ConsentGate | `63.1`, `63.2`
 * Composed | `64.1`, `64.2`
 */
export const REQUIRED_CONDITION_MODULE_ROW_IDS: ConditionModuleCoverage = {
  PaymentObligation: ["56.1", "56.2"] as const,
  TimeLock: ["57"] as const,
  SubjectInitiated: ["58"] as const,
  HeartbeatMissed: ["59", "62.1", "62.2"] as const,
  OracleAttestation: ["60.1", "60.2"] as const,
  MultiPartySignal: ["61", "70", "69.2"] as const,
  DeadManSwitch: ["62.1", "62.2", "69.1"] as const,
  ConsentGate: ["63.1", "63.2"] as const,
  Composed: ["64.1", "64.2"] as const,
} as const;

/** Cross-spec invariant: 7 views in coverage sidecar. */
export const VIEW_COUNT = 7 as const;

/** Cross-spec invariant: 9 condition modules in coverage sidecar. */
export const CONDITION_MODULE_COUNT = 9 as const;

export const VIEW_NAMES: readonly (keyof ViewCoverage)[] = [
  "Enforcement",
  "TamperProof",
  "SelectiveDisclosure",
  "Commercial",
  "Legal",
  "UseCaseFlex",
  "PartnerFit",
] as const;

export const CONDITION_MODULE_NAMES: readonly (keyof ConditionModuleCoverage)[] = [
  "PaymentObligation",
  "TimeLock",
  "SubjectInitiated",
  "HeartbeatMissed",
  "OracleAttestation",
  "MultiPartySignal",
  "DeadManSwitch",
  "ConsentGate",
  "Composed",
] as const;
