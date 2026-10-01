import { describe, it, expect } from "vitest";
import * as M4 from "../../src/m4-imports.js";

describe("M4 facade smoke (re-export from @cealis/v3-configurator)", () => {
  it("re-exports PDA type catalog", () => {
    // Verify named exports exist (types are erased at runtime — check sentinel
    // constants from the source-of-truth modules in v3-configurator).
    expect(Array.isArray(M4.PDA_ROOT_FIELD_NAMES)).toBe(true);
    expect(M4.PDA_ROOT_FIELD_NAMES.length).toBeGreaterThan(0);
    expect(Array.isArray(M4.PARTNER_INSPECTION_PRIMITIVE_FIELDS)).toBe(true);
    expect(Array.isArray(M4.AUDIT_TRAIL_FIELD_NAMES)).toBe(true);
    expect(Array.isArray(M4.CATEGORY_VALUES)).toBe(true);
    expect(Array.isArray(M4.TEST_EXITED_ON_VALUES)).toBe(true);
  });

  it("PDA_ROOT_FIELD_NAMES has at least 28 fields (S2-1 §3.3 29-field structure)", () => {
    expect(M4.PDA_ROOT_FIELD_NAMES.length).toBeGreaterThanOrEqual(28);
  });

  it("CATEGORY_VALUES enumerates valid PDA categories", () => {
    expect(M4.CATEGORY_VALUES.length).toBeGreaterThan(0);
  });

  it("re-exports redaction surface (signature-only at M4 Phase A; body at Phase E)", () => {
    expect(typeof M4.redact).toBe("function");
    expect(typeof M4.findPiiMatch).toBe("function");
    expect(M4.PII_EXCLUSION_PATTERNS).toBeDefined();
  });

  // FIXTURES NOTE: M4's tsconfig excludes fixtures/ from compilation, so
  // `@cealis/v3-configurator/fixtures` does not resolve at this Phase A
  // baseline. Fixture loading is deferred to Phase E integration tests with
  // a source-file-pointer load pattern. See SPEC-COMPLIANCE-GUARD-M5 §0 and
  // the internal Phase E build brief for the resolution.
});
