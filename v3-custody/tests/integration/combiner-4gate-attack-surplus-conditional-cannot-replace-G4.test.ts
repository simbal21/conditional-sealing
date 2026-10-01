import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, GateKind, combineAndDecrypt } from "../../src/index.js";
import { makeFixture, profileKofN } from "./combiner-testkit.js";

describe("PRO-498 R2 negative vector", () => {
  it("rejects Lit + G3 + surplus conditional shares when G4 is absent", () => {
    const profile = profileKofN();
    const base = makeFixture({ profile });
    const evidence = [
      ...base.sigmas.evidence.filter((item) => item.gateKind !== GateKind.G4),
      {
        ...base.sigmas.evidence[3]!,
        conditionalRecipientIndex: 2,
        sigmaBytes: new Uint8Array([4, 2, 0x99]),
        gateRecipientPubkey: base.registrySnapshots.commitSnapshot.gateRecipientPubkeys.get(`${GateKind.ConditionalRecipient}:2`)!,
        metadata: { ...base.sigmas.evidence[3]!.metadata, stanzaIndex: 5 },
      },
    ];
    const result = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET);
      expect(result.subCodes).toContain("ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT");
    }
  });
});
