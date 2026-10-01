import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES } from "../../src/errors.js";
import { assertVendorFamiliesDisjoint, normalizeVendorFamily } from "../../src/g2-lit/vendor-family-normalize.js";

describe("G2 Lit cross-vendor rejection", () => {
  it("rejects Lit Intel vs G4 Intel and Lit AMD vs G4 AMD", () => {
    const litIntel = normalizeVendorFamily({ vendorRoot: "Intel", isolationTechnology: "SGX" });
    const g4Intel = normalizeVendorFamily({ vendorRoot: "Intel", isolationTechnology: "TDX" });
    const litAmd = normalizeVendorFamily({ vendorRoot: "AMD", isolationTechnology: "SEV-SNP" });
    const g4Amd = normalizeVendorFamily({ vendorRoot: "AMD Root", isolationTechnology: "SEV SNP" });
    expect(() => assertVendorFamiliesDisjoint(litIntel, g4Intel)).toThrow(CUSTODY_ERROR_CODES.CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION);
    expect(() => assertVendorFamiliesDisjoint(litAmd, g4Amd)).toThrow(CUSTODY_ERROR_CODES.CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION);
  });
});
