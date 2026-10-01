// Foundation test — §7.9 6-row constraint-count budget catalog.
//
// Phase C `pnpm run setup:circuits` emits per-circuit constraint counts to
// `v3-sd/reports/M6-sd-pipeline/constraint-report.json`. Phase F
// asserts every circuit ≤ §7.9 max.

import { describe, it, expect } from "vitest";
import {
  CONSTRAINT_BUDGETS,
  CONSTRAINT_BUDGET_KEYS,
  CONSTRAINT_BUDGET_ROW_COUNT,
} from "../../src/setup/constraint-budgets.js";

describe("§7.9 constraint budget catalog (6 rows)", () => {
  it("exactly 6 rows", () => {
    expect(CONSTRAINT_BUDGETS.length).toBe(6);
    expect(CONSTRAINT_BUDGET_KEYS.length).toBe(6);
    expect(CONSTRAINT_BUDGET_ROW_COUNT).toBe(6);
  });

  it("verbatim values from §7.9 lines 821-826", () => {
    const expected = [
      { circuit: "equality_d16", target: 35_000, max: 60_000 },
      { circuit: "non_equality_d16", target: 40_000, max: 70_000 },
      { circuit: "range_64_d16", target: 55_000, max: 90_000 },
      { circuit: "inline_set_32_d16", target: 80_000, max: 130_000 },
      { circuit: "merkle_set_d16", target: 100_000, max: 160_000 },
      { circuit: "aggregate_8_leaves", target: 250_000, max: 400_000 },
    ];
    for (const [idx, row] of CONSTRAINT_BUDGETS.entries()) {
      expect(row.circuit).toBe(expected[idx]?.circuit);
      expect(row.target).toBe(expected[idx]?.target);
      expect(row.max).toBe(expected[idx]?.max);
    }
  });

  it("target ≤ max for every row", () => {
    for (const row of CONSTRAINT_BUDGETS) {
      expect(row.target).toBeLessThanOrEqual(row.max);
    }
  });
});
