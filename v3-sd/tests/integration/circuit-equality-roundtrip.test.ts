import { describe, expect, it } from "vitest";

import { generatePlonkProof, makeCircuitFixture, toPublicInputArray } from "../../src/prove/index.js";

describe("equality circuit roundtrip", () => {
  it("generates witness, PLONK proof, and verifies off-chain", { timeout: 120_000 }, async () => {
    const fixture = await makeCircuitFixture("equality");
    const result = generatePlonkProof("equality", fixture.input);

    expect(result.status).toBe("complete");
    expect(result.verified).toBe(true);
    expect(result.publicSignals).toEqual(toPublicInputArray(fixture.publicInputs));
  });
});
