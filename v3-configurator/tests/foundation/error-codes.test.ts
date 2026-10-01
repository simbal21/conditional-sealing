// Foundation: Stage-indexed error code formatter.

import { describe, expect, it } from "vitest";
import {
  formatStageCode,
  parseStageCode,
  STAGE_CODE_PREFIX,
  STAGE_VALUES,
  type Stage,
} from "../../src/errors/stage-codes.js";

describe("@cealis/v3-configurator — error codes (§1.3 + §4.7)", () => {
  it("STAGE_VALUES contains 1..5 in order", () => {
    expect(STAGE_VALUES).toEqual([1, 2, 3, 4, 5]);
  });

  it("STAGE_CODE_PREFIX is 'S2_4_STAGE_'", () => {
    expect(STAGE_CODE_PREFIX).toBe("S2_4_STAGE_");
  });

  it("formatStageCode produces the §4.7 example shape", () => {
    const formatted = formatStageCode(
      4,
      "cealis_class_wide_halt_opt_out",
      "LEGAL_EFFECT_FORBIDDEN",
    );
    expect(formatted).toBe(
      "S2_4_STAGE_4.cealis_class_wide_halt_opt_out.LEGAL_EFFECT_FORBIDDEN",
    );
  });

  it("formatStageCode rejects invalid stages", () => {
    expect(() => formatStageCode(0 as Stage, "x", "Y")).toThrow();
    expect(() => formatStageCode(6 as Stage, "x", "Y")).toThrow();
  });

  it("formatStageCode rejects surface_names with whitespace or dots", () => {
    expect(() => formatStageCode(2, "bad name", "Y")).toThrow();
    expect(() => formatStageCode(2, "bad.name", "Y")).toThrow();
    expect(() => formatStageCode(2, "", "Y")).toThrow();
  });

  it("formatStageCode rejects codes with whitespace or dots", () => {
    expect(() => formatStageCode(2, "x", "BAD CODE")).toThrow();
    expect(() => formatStageCode(2, "x", "BAD.CODE")).toThrow();
    expect(() => formatStageCode(2, "x", "")).toThrow();
  });

  it("parseStageCode round-trips formatStageCode output for all 5 stages", () => {
    for (const stage of STAGE_VALUES) {
      const formatted = formatStageCode(stage, "test_surface", "TEST_CODE");
      const parsed = parseStageCode(formatted);
      expect(parsed).not.toBeNull();
      if (parsed === null) continue;
      expect(parsed.stage).toBe(stage);
      expect(parsed.surface_name).toBe("test_surface");
      expect(parsed.code).toBe("TEST_CODE");
    }
  });

  it("parseStageCode returns null for non-canonical strings", () => {
    expect(parseStageCode("S2_4_STAGE_0.x.Y")).toBeNull();
    expect(parseStageCode("S2_4_STAGE_4.x")).toBeNull();
    expect(parseStageCode("random string")).toBeNull();
    expect(parseStageCode("")).toBeNull();
  });
});
