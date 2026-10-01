import { describe, expect, it } from "vitest";

import { generatePlonkProof, makeCircuitFixture, toPublicInputArray } from "../../src/prove/index.js";

describe("range circuit roundtrip", () => {
  it("generates witness, PLONK proof, and verifies off-chain", { timeout: 120_000 }, async () => {
    const fixture = await makeCircuitFixture("range");
    const result = generatePlonkProof("range", fixture.input);

    expect(result.status).toBe("complete");
    expect(result.verified).toBe(true);
    expect(result.publicSignals).toEqual(toPublicInputArray(fixture.publicInputs));
  });
});
