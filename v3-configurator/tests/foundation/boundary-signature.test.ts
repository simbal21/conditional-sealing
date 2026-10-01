// Foundation: boundary-decision cascade signature (§3.6).

import { describe, expect, it } from "vitest";
import {
  classifySurface,
  type BoundaryClassification,
} from "../../src/validate/boundary/types.js";
import {
  CATEGORY_VALUES,
  TEST_EXITED_ON_VALUES,
} from "../../src/types/categories.js";

describe("@cealis/v3-configurator — boundary cascade signature (§3.6)", () => {
  it("classifySurface is callable as a function", () => {
    expect(typeof classifySurface).toBe("function");
  });

  it("classifySurface returns a BoundaryClassification-shaped value", () => {
    const result: BoundaryClassification = classifySurface("test_surface");
    expect(result).toBeDefined();
    expect(typeof result.test_exited_on).toBe("string");
    expect(typeof result.category).toBe("string");
    expect(typeof result.rationale).toBe("string");
    expect(result.derivation_pointer === null || typeof result.derivation_pointer === "string").toBe(
      true,
    );
  });

  it("classifySurface result has a valid test_exited_on value", () => {
    const result = classifySurface("any");
    expect(TEST_EXITED_ON_VALUES).toContain(result.test_exited_on);
  });

  it("classifySurface result has a valid category value", () => {
    const result = classifySurface("any");
    expect(CATEGORY_VALUES).toContain(result.category);
  });

  it("classifySurface rationale is non-empty", () => {
    const result = classifySurface("any");
    expect(result.rationale.length).toBeGreaterThan(0);
  });
});
