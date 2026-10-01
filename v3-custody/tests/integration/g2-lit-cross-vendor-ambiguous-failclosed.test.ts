import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES } from "../../src/errors.js";
import { assertVendorFamiliesDisjoint, normalizeVendorFamily } from "../../src/g2-lit/vendor-family-normalize.js";

describe("G2 Lit ambiguous vendor fail-closed", () => {
  it("returns AMBIGUOUS and fails closed", () => {
    const lit = normalizeVendorFamily({ vendorRoot: "unclassified lab root" });
    const g4 = normalizeVendorFamily({ vendorRoot: "AWS Root", isolationTechnology: "Nitro" });
    expect(lit.family).toBe("AMBIGUOUS");
    expect(() => assertVendorFamiliesDisjoint(lit, g4)).toThrow(CUSTODY_ERROR_CODES.CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION);
  });
});
