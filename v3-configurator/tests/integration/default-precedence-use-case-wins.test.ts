import { describe, expect, it } from "vitest";
import { applyDefaultPrecedence } from "../../src/defaults/index.js";

describe("§13.4 default precedence", () => {
  it("applies use-case defaults when only use-case index is present", () => {
    const result = applyDefaultPrecedence({ use_case: "kyc" });
    expect(result.values.g3_choice).toBe("dcipher");
    expect(
      result.inspection_records.find(
        (record) => record.field_path === "g3_choice",
      )?.default_index_used,
    ).toBe("use-case");
  });

  it("falls back to archetype defaults when use-case index is absent", () => {
    const result = applyDefaultPrecedence({ archetype: "archival" });
    expect(result.values.shred_authority).toBe("Disabled");
    expect(
      result.inspection_records.find(
        (record) => record.field_path === "shred_authority",
      )?.default_index_used,
    ).toBe("archetype");
  });

  it("uses use-case value and records superseded archetype fallback when both indexes set the same field", () => {
    const result = applyDefaultPrecedence({
      use_case_defaults: { g3_choice: "dcipher" },
      archetype_defaults: { g3_choice: "drand" },
    });
    const g3 = result.inspection_records.find(
      (record) => record.field_path === "g3_choice",
    );
    expect(result.values.g3_choice).toBe("dcipher");
    expect(g3?.default_index_used).toBe("use-case");
    expect(g3?.superseded_archetype_fallback).toBe("drand");
  });
});
