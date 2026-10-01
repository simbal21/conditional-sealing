import { describe, expect, it } from "vitest";
import { GateKind, combineAndDecrypt } from "../../src/index.js";
import { makeFixture } from "./combiner-testkit.js";

describe("combiner extra sigma rejection", () => {
  it("rejects sigma evidence not bound by the fixed-only commit profile", () => {
    const base = makeFixture();
    const extra = {
      ...base.sigmas.evidence[0]!,
      gateKind: GateKind.ConditionalRecipient,
      conditionalRecipientIndex: 0,
      sigmaBytes: new Uint8Array([4, 0, 1]),
      metadata: { ...base.sigmas.evidence[0]!.metadata, stanzaIndex: 3 },
    };
    const result = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence: [...base.sigmas.evidence, extra] },
    });
    expect(result.ok).toBe(false);
  });
});
