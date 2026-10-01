// M8 Round 3 — SD bundle verified via M2 IDisclosureRegistry on-chain
// (Step 4 + S2-2 §9.15 + S2-7 §11.1 verifyAndCommitDisclosure).
//
// The on-chain verify path is implemented by M6 — `verifyAndCommitDisclosure`
// on the DisclosureRegistry contract. The partner SDK consults this via
// partner-controlled RPC. This test asserts the ABI presence at the M2
// surface (live invocation lives in Phase G smoke).

import { describe, it, expect } from "vitest";
import {
  runRound3Structural,
  isVerifyAndCommitDisclosureAbiPresent,
} from "../../src/rounds/round3.js";
import { M2_ABIS } from "../../src/m2-imports.js";

describe("Round 3 — SD bundle verify on-chain wiring (M2 §9.15)", () => {
  it("M2 DisclosureRegistry ABI exposes verifyAndCommitDisclosure", () => {
    expect(isVerifyAndCommitDisclosureAbiPresent()).toBe(true);
  });

  it("Round 3 result records onChainVerifyCalled=true (wiring witness)", async () => {
    const result = await runRound3Structural();
    expect(result.onChainVerifyCalled).toBe(true);
  });

  it("DisclosureRegistry ABI also exposes verifyDisclosureProof (read-only path)", () => {
    const abi = M2_ABIS.DisclosureRegistry;
    const fn = abi.find(
      (it) =>
        (it as { type?: string; name?: string }).type === "function" &&
        (it as { type?: string; name?: string }).name === "verifyDisclosureProof",
    );
    expect(fn).toBeDefined();
  });

  it("DisclosureRevocationRegistry contract is wired into the M2 surface", () => {
    expect(M2_ABIS.DisclosureRevocationRegistry).toBeDefined();
    expect(M2_ABIS.DisclosureRevocationRegistry.length).toBeGreaterThan(0);
  });

  it("partner SDK accepts the SD bundle via stub verifier (independence path)", async () => {
    // Implicit: runRound3Structural() internally calls verifySdBundle()
    // and would throw DEMO_ERR_BUNDLE_VERIFY_FAIL if the SDK rejected.
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.status).toBe("complete");
  });
});
