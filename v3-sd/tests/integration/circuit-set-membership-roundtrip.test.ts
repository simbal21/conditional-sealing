import { describe, expect, it } from "vitest";

import { generatePlonkProof, makeCircuitFixture, toPublicInputArray } from "../../src/prove/index.js";

describe("set-membership circuit roundtrip", () => {
  it("generates witness, PLONK proof, and verifies off-chain", { timeout: 120_000 }, async () => {
    const fixture = await makeCircuitFixture("set_membership");
    const result = generatePlonkProof("set_membership", fixture.input);

    expect(result.status).toBe("complete");
    expect(result.verified).toBe(true);
    expect(result.publicSignals).toEqual(toPublicInputArray(fixture.publicInputs));
  });
});
