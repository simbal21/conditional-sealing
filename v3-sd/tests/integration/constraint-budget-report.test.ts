import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { CONSTRAINT_BUDGETS } from "../../src/setup/index.js";

const REPORT_PATH = resolve(process.cwd(), "reports", "M6-sd-pipeline", "constraint-report.json");

interface ConstraintRow {
  readonly circuit: string;
  readonly measured: number;
  readonly max: number;
}

describe("M6 Phase C constraint budget report", () => {
  it("keeps every measured circuit at or below the §7.9 max", () => {
    const report = JSON.parse(readFileSync(REPORT_PATH, "utf-8")) as { readonly budgets: readonly ConstraintRow[] };
    const maxByKey = new Map(CONSTRAINT_BUDGETS.map((row) => [row.circuit, row.max]));

    for (const row of report.budgets) {
      const lockedMax = maxByKey.get(row.circuit as never);
      expect(lockedMax, `missing locked budget for ${row.circuit}`).toBeDefined();
      expect(row.max).toBe(lockedMax);
      expect(row.measured).toBeLessThanOrEqual(row.max);
    }
  });
});
