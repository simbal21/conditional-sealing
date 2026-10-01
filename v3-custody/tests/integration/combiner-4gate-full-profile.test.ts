import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, combineAndDecrypt } from "../../src/index.js";
import { makeFixture, profileKofN } from "./combiner-testkit.js";

describe("combiner 4-gate full profile", () => {
  it("accepts active 0x0302 full profile with disjoint Phase 2 TEE vendors", () => {
    const result = combineAndDecrypt(
      makeFixture({
        profile: profileKofN(),
        phase: 2,
        litVendorFamily: "Intel TDX",
        g4VendorFamily: "AWS Nitro",
      }),
    );
    expect(result.ok).toBe(true);
  });

  it("rejects attempts to use a 3-gate profile for an active 4-gate commit", () => {
    const base = makeFixture({ profile: profileKofN() });
    const evidence = base.sigmas.evidence.map((item) => ({
      ...item,
      metadata: { ...item.metadata, gateCount: 3 },
    }));
    const result = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET);
  });

  it("skips cross-vendor check for Phase 1 and enforces fail-closed for Phase 2", () => {
    const phase1 = combineAndDecrypt(
      makeFixture({ phase: 1, litVendorFamily: "Intel SGX", g4VendorFamily: "Intel TDX" }),
    );
    expect(phase1.ok).toBe(true);

    const sameVendor = combineAndDecrypt(
      makeFixture({ phase: 2, litVendorFamily: "Intel SGX", g4VendorFamily: "Intel TDX" }),
    );
    expect(sameVendor.ok).toBe(false);
    if (!sameVendor.ok) {
      expect(sameVendor.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION);
    }

    const ambiguous = combineAndDecrypt(
      makeFixture({ phase: 2, litVendorFamily: "unknown", g4VendorFamily: "AWS Nitro" }),
    );
    expect(ambiguous.ok).toBe(false);
    if (!ambiguous.ok) {
      expect(ambiguous.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION);
    }
  });

  it("routes dcipher-backed 4-gate profiles and rejects missing cross-vendor evidence", () => {
    const dcipher = combineAndDecrypt(makeFixture({ profile: profileKofN(), g3Choice: 0 }));
    expect(dcipher.ok).toBe(true);

    const missingVendor = combineAndDecrypt(makeFixture({ profile: profileKofN(), phase: 2 }));
    expect(missingVendor.ok).toBe(false);
    if (!missingVendor.ok) {
      expect(missingVendor.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION);
    }
  });

  it("infers profiles from commit metadata when no explicit profile override is present", () => {
    const oneOfOne = makeFixture({
      profile: { kind: "RECIPIENT_1_OF_1" },
      evidence: undefined,
    });
    const withoutOneOfOneOverride = oneOfOne.sigmas.evidence.map((item) => ({
      ...item,
      metadata: Object.fromEntries(
        Object.entries(item.metadata).filter(([key]) => key !== "profileKind" && key !== "accessStructureProfile"),
      ),
    }));
    expect(combineAndDecrypt({ ...oneOfOne, sigmas: { ...oneOfOne.sigmas, evidence: withoutOneOfOneOverride } }).ok).toBe(
      true,
    );

    const kofn = makeFixture({ profile: profileKofN() });
    const withoutKofnOverride = kofn.sigmas.evidence.map((item) => ({
      ...item,
      metadata: Object.fromEntries(
        Object.entries(item.metadata).filter(([key]) => key !== "profileKind" && key !== "accessStructureProfile"),
      ),
    }));
    expect(combineAndDecrypt({ ...kofn, sigmas: { ...kofn.sigmas, evidence: withoutKofnOverride } }).ok).toBe(true);

    const gateCountOnly = kofn.sigmas.evidence.map((item) => ({
      ...item,
      metadata: {
        ...Object.fromEntries(
          Object.entries(item.metadata).filter(([key]) => key !== "profileKind" && key !== "accessStructureProfile"),
        ),
        gateCount: 4,
      },
    }));
    expect(combineAndDecrypt({ ...kofn, sigmas: { ...kofn.sigmas, evidence: gateCountOnly } }).ok).toBe(true);
  });
});
