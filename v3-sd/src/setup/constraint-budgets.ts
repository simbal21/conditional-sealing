// §7.9 lines 815-826 — Constraint-count budget. Phase A LOCKED.
//
// Phase C `pnpm run setup:circuits` writes the measured count per circuit to
// `v3-sd/reports/M6-sd-pipeline/constraint-report.json`. Phase F
// loads + asserts target/max from this catalog.
//
// SD-PLONK-005 conformance: FAIL if any circuit exceeds `max`.
// SD-PLONK-005 warning:     WARN if circuit exceeds `target` but ≤ max.

export interface ConstraintBudgetRow {
  /** Stable identifier consumed by Phase C report keys. */
  readonly circuit: ConstraintBudgetKey;
  readonly description: string;
  readonly target: number;
  readonly max: number;
}

export const CONSTRAINT_BUDGET_KEYS = Object.freeze([
  "equality_d16",
  "non_equality_d16",
  "range_64_d16",
  "inline_set_32_d16",
  "merkle_set_d16",
  "aggregate_8_leaves",
] as const);

export type ConstraintBudgetKey = typeof CONSTRAINT_BUDGET_KEYS[number];

export const CONSTRAINT_BUDGETS: ReadonlyArray<ConstraintBudgetRow> = Object.freeze([
  {
    circuit: "equality_d16",
    description: "equality + Merkle depth 16",
    target: 35_000,
    max: 60_000,
  },
  {
    circuit: "non_equality_d16",
    description: "non-equality + Merkle depth 16",
    target: 40_000,
    max: 70_000,
  },
  {
    circuit: "range_64_d16",
    description: "range 64-bit + Merkle depth 16",
    target: 55_000,
    max: 90_000,
  },
  {
    circuit: "inline_set_32_d16",
    description: "inline set membership 32 + Merkle depth 16",
    target: 80_000,
    max: 130_000,
  },
  {
    circuit: "merkle_set_d16",
    description: "Merkle-set membership depth 16 + field Merkle depth 16",
    target: 100_000,
    max: 160_000,
  },
  {
    circuit: "aggregate_8_leaves",
    description: "aggregate Claim, 8 leaves",
    target: 250_000,
    max: 400_000,
  },
]);

export const CONSTRAINT_BUDGET_ROW_COUNT = 6 as const;
