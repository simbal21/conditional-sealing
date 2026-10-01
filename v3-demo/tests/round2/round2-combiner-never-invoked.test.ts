// Step 8 — combiner is NEVER invoked during Round 2.
//
// Round 2's normative test is ABSENCE-OF-EVENT for RevealAuthorized. Because
// no authorization fires, the combiner.combineAndDecrypt entry point is
// NEVER REACHED. This test asserts the spy invocation count stays at 0.

import { describe, it, expect } from "vitest";
import {
  runRound2,
  makeDefaultRound2Dependencies,
  type Round2ContractAddresses,
} from "../../src/rounds/round2.js";

const ADDRESSES: Round2ContractAddresses = {
  conditionEngine: "0x7777777777777777777777777777777777777777",
  shredRegistry: "0x8888888888888888888888888888888888888888",
};

describe("Round 2 — combiner NEVER invoked (Step 8)", () => {
  it("combinerSpy.invocationCount === 0 after Round 2 completes", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.combinerInvocationCount).toBe(0);
    expect(deps.combinerSpy.invocationCount).toBe(0);
  });

  it("Round 2 does NOT exercise Shamir.combine / AEAD decrypt (no σ collection)", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    // combinerInvocationCount === 0 implies neither Shamir.combine nor
    // AEAD decrypt was called (both live downstream of combineAndDecrypt).
    expect(result.combinerInvocationCount).toBe(0);
  });

  it("Spy can be MANUALLY tripped to confirm Round 2 detects combiner invocation", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    // Simulate a bug where combiner gets invoked. Round 2 must throw.
    deps.combinerSpy.recordInvocation("0xdead");
    await expect(runRound2(deps)).rejects.toMatchObject({
      code: "DEMO_ERR_UNEXPECTED_EVENT",
    });
  });
});
