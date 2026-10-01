import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, combineAndDecrypt } from "../../src/index.js";
import { makeFixture, profile1of1 } from "./combiner-testkit.js";

describe("combiner Mode 3 rejection", () => {
  it("rejects WALLET_EIP1271 conditional recipient stanzas at V2 launch", () => {
    const result = combineAndDecrypt(makeFixture({ profile: profile1of1(), mode3: true }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_MODE3_RESERVED);
  });

  it("rejects Mode 3 metadata labels even before stanza payload interpretation", () => {
    const base = makeFixture({ profile: profile1of1() });
    const numericMode = base.sigmas.evidence.map((item, index) =>
      index === 3 ? { ...item, metadata: { ...item.metadata, deliveryMode: 3 } } : item,
    );
    const numericResult = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence: numericMode } });
    expect(numericResult.ok).toBe(false);
    if (!numericResult.ok) expect(numericResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_MODE3_RESERVED);

    const labelMode = base.sigmas.evidence.map((item, index) =>
      index === 3 ? { ...item, metadata: { ...item.metadata, deliveryMode: "WALLET_EIP1271" } } : item,
    );
    const labelResult = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence: labelMode } });
    expect(labelResult.ok).toBe(false);
    if (!labelResult.ok) expect(labelResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_MODE3_RESERVED);
  });
});
