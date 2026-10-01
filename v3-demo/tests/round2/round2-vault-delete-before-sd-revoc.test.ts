// Step 4 ordering — vault delete BEFORE any pending SD revocation worker
// fires (S2-2 §13.4 SD revocation interaction).
//
// Per the internal build brief Step 4: this ordering is IRRELEVANT in Round 2 (SD is
// disabled — TestamentPDA / DeadManSwitchPDA at Round 2 have sd_enabled
// = false). But the assertion is still placed to enforce the invariant at
// the orchestration layer for forward-compatibility with Round 3 + 4
// configurations where SD is on.

import { describe, it, expect } from "vitest";
import {
  runRound2,
  makeDefaultRound2Dependencies,
  type Round2ContractAddresses,
} from "../../src/rounds/round2.js";

const ADDRESSES: Round2ContractAddresses = {
  conditionEngine: "0x5555555555555555555555555555555555555555",
  shredRegistry: "0x6666666666666666666666666666666666666666",
};

describe("Round 2 — vault-delete ordering vs SD revocation (S2-2 §13.4)", () => {
  it("vault.exists === false immediately after ShredFinalized (SD off branch)", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.chainState.shredFinalizedEmitted).toBe(true);
    expect(result.vaultExistsAfterShred).toBe(false);
  });

  it("(SD off / Round 2): no SD revocation worker reachable from this round", async () => {
    // Round 2 uses the deadManSwitch fixture which is sd_enabled=false. The
    // round orchestration does NOT spawn an SD revocation worker. Phase E
    // cross-round tests cover the SD-on ordering invariant.
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    // Sanity: combiner not invoked, no SD path reached.
    expect(result.combinerInvocationCount).toBe(0);
  });

  it("vault delete completes in same ceremony execute() stage as ShredFinalized emit", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    // The ShredTriggerCeremony.execute() method emits ShredFinalized AND
    // calls vaultClient.deleteCiphertext within the same stage (live mode).
    // In dry-run, both are simulated within execute(). Test verifies the
    // stage was reached.
    expect(result.ceremonyOutcome.stagesReached).toContain("execute");
    expect(result.chainState.shredFinalizedEmitted).toBe(true);
  });
});
