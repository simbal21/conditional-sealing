import { describe, expect, it } from "vitest";
import { buildCleartextPlan } from "../../../tests/integration/helpers.js";

describe("SD plan build", () => {
  it("assigns deterministic field indexes after canonical ordering", () => {
    const plan = buildCleartextPlan();
    expect(plan.sd_plan.sd_enabled).toBe(true);
    expect(plan.ordered_fields.map((f) => f.field_index)).toEqual([0, 1]);
  });
});
