import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, GateKind, combineAndDecrypt } from "../../src/index.js";
import { reconstructFileKey } from "../../src/combiner/index.js";
import { makeFixture, profile1of1 } from "./combiner-testkit.js";

describe("combiner missing mandatory sigma", () => {
  for (const gateKind of [GateKind.LitV3, GateKind.Drand, GateKind.G4] as const) {
    it(`rejects missing mandatory gate ${gateKind}`, () => {
      const base = makeFixture();
      const input = {
        ...base,
        sigmas: {
          ...base.sigmas,
          evidence: base.sigmas.evidence.filter((evidence) => evidence.gateKind !== gateKind),
        },
      };
      const result = combineAndDecrypt(input);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET);
        expect(result.subCodes).toContain("ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT");
      }
    });
  }

  it("rejects duplicate gates and missing share material before Shamir reconstruction", () => {
    const base = makeFixture();
    const duplicate = [...base.sigmas.evidence];
    duplicate[1] = { ...duplicate[0]!, sigmaBytes: new Uint8Array([1, 1, 1]) };
    const duplicateResult = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence: duplicate } });
    expect(duplicateResult.ok).toBe(false);
    if (!duplicateResult.ok) expect(duplicateResult.subCodes).toContain("ERR_DUPLICATE_SIGMA_GATE");

    const noShare = base.sigmas.evidence.map((item, index) =>
      index === 2
        ? {
            ...item,
            metadata: Object.fromEntries(Object.entries(item.metadata).filter(([key]) => key !== "shareHex")),
          }
        : item,
    );
    const noShareResult = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence: noShare } });
    expect(noShareResult.ok).toBe(false);
    if (!noShareResult.ok) expect(noShareResult.subCodes).toContain("ERR_SHARE_UNAUTHORIZED");

    const badShare = base.sigmas.evidence.map((item, index) =>
      index === 2 ? { ...item, metadata: { ...item.metadata, shareHex: "0x01" } } : item,
    );
    const badShareResult = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence: badShare } });
    expect(badShareResult.ok).toBe(false);
    if (!badShareResult.ok) expect(badShareResult.subCodes).toContain("ERR_SHARE_RECORD_VALUE_LENGTH");
  });

  it("maps adapter verification failures to gate-specific custody errors", () => {
    const base = makeFixture();
    const failedDrand = base.sigmas.evidence.map((item) =>
      item.gateKind === GateKind.Drand
        ? { ...item, metadata: { ...item.metadata, verified: "false", verifyCode: "ERR_DRAND_ROUND_MISMATCH" } }
        : item,
    );
    const result = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence: failedDrand } });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_SIG_INVALID);
      expect(result.subCodes).toContain("ERR_DRAND_ROUND_MISMATCH");
    }

    const g4Failed = base.sigmas.evidence.map((item) =>
      item.gateKind === GateKind.G4
        ? { ...item, metadata: { ...item.metadata, verified: "false", verifyCode: "REASON_0x02" } }
        : item,
    );
    const g4Result = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence: g4Failed } });
    expect(g4Result.ok).toBe(false);
    if (!g4Result.ok) expect(g4Result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_REFUSED);

    const withRecipient = makeFixture({ profile: profile1of1() });
    const conditionalFailed = withRecipient.sigmas.evidence.map((item) =>
      item.gateKind === GateKind.ConditionalRecipient
        ? { ...item, metadata: { ...item.metadata, verified: "false", verifyCode: "not safe to echo" } }
        : item,
    );
    const conditionalResult = combineAndDecrypt({
      ...withRecipient,
      sigmas: { ...withRecipient.sigmas, evidence: conditionalFailed },
    });
    expect(conditionalResult.ok).toBe(false);
    if (!conditionalResult.ok) {
      expect(conditionalResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET);
      expect(conditionalResult.subCodes).toContain("ERR_SHARE_UNAUTHORIZED");
    }
  });

  it("surfaces M1 typed Shamir rejection without local reconstruction fallback", () => {
    expect(() => reconstructFileKey({ shares: [], profile: { kind: "FIXED_ONLY" } })).toThrow();
  });
});
