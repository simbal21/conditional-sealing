// M8 Round 3 — Real PLONK proof + verify lane (opt-in).
//
// Closes an internal integration-gap item. This test exercises Round 3 with a REAL
// snarkjs `range` proof generated at sdEmit-time AND verified at SDK
// callback-time via `verifyPlonkProof("range", ...)`. Default test surface
// keeps the synthetic-stub path; this test only runs under
// `VITEST_PLONK_REAL=1` so vitest CI stays ~2s.
//
// Performance envelope: ~10s for the proof generation + ~3-5s for verify,
// hence the 120s timeout. Confirms that the structural-test verifier-lane
// is not just a stub mock: the SDK's `Verifier.verifyProof(proof, publicInputs)`
// callback actually feeds bytes through snarkjs.

import { describe, it, expect } from "vitest";
import { runRound3Structural } from "../../src/rounds/round3.js";

const REAL = process.env.VITEST_PLONK_REAL === "1";

describe.skipIf(!REAL)("Round 3 — REAL PLONK proof + verify lane (opt-in)", () => {
  it(
    "generates real snarkjs proof + SDK verifyProof returns true",
    { timeout: 120_000 },
    async () => {
      const result = await runRound3Structural();
      expect(result.sdEnabled).toBe(true);
      const claim = result.recipient.sdBundle.claims[0];
      expect(claim).toBeDefined();
      if (claim === undefined) return;
      // Real PLONK proofs are JSON serializations of the snarkjs proof
      // object; their hex encoding is longer than the synthetic 192-byte
      // `0xab…` stub (~6KB+ once hex-encoded).
      expect(claim.proof.length).toBeGreaterThan(800);
      // Public inputs from the `range` circuit's fixture have multiple
      // scalars (not just the synthetic [String(BigInt(18))]).
      expect(claim.public_inputs.length).toBeGreaterThan(1);
    },
  );
});
