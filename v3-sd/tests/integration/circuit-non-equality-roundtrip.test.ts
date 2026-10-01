import { describe, expect, it } from "vitest";

import { generatePlonkProof, makeCircuitFixture, toPublicInputArray } from "../../src/prove/index.js";

describe("non-equality circuit roundtrip", () => {
  it("generates witness, PLONK proof, and verifies off-chain", { timeout: 120_000 }, async () => {
    const fixture = await makeCircuitFixture("non_equality");
    const result = generatePlonkProof("non_equality", fixture.input);

    expect(result.status).toBe("complete");
    expect(result.verified).toBe(true);
    expect(result.publicSignals).toEqual(toPublicInputArray(fixture.publicInputs));
  });
});
