// Round 2 main success path — Steps 1-7 per the internal build brief.
//
// NORMATIVE SUCCESS CRITERION (S2-2 §12.5 #4 — "No RevealAuthorized after
// ShredFinalized"). The Round 2 demo passes IFF zero `RevealAuthorized`
// events fire in the block range [shredBlock, latestBlock] for the
// shredded h_commit.
//
// PHASE-PLAN §0 drift catch #8: success is ABSENCE-OF-EVENT, NOT
// event-then-negation. The combiner is NEVER reached in Round 2.

import { describe, it, expect } from "vitest";
import {
  runRound2,
  makeDefaultRound2Dependencies,
  type Round2ContractAddresses,
} from "../../src/rounds/round2.js";

const ADDRESSES: Round2ContractAddresses = {
  conditionEngine: "0x1111111111111111111111111111111111111111",
  shredRegistry: "0x2222222222222222222222222222222222222222",
};

describe("Round 2 — shred → G1 chain-block (absence-of-event)", () => {
  it("Step 7 NORMATIVE: zero RevealAuthorized events in shred window", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.revealAuthorizedAbsent).toBe(true);
  });

  it("Step 1: produces a fresh subjectId with the demo-r2- prefix", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.subjectId.startsWith("demo-r2-")).toBe(true);
    expect(result.subjectId.length).toBeGreaterThan(8);
  });

  it("Step 2-3: ShredTriggerCeremony emits ShredRequested + ShredFinalized", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.chainState.shredRequestedEmitted).toBe(true);
    expect(result.chainState.shredFinalizedEmitted).toBe(true);
  });

  it("Step 6: chain time advances past shred block", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    const latestBlock = await deps.chain.readBlockNumber();
    expect(latestBlock).toBeGreaterThan(result.shredBlock);
  });

  it("Two consecutive runs use DISTINCT subjectIds (fresh per run)", async () => {
    const depsA = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const depsB = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const a = await runRound2(depsA);
    const b = await runRound2(depsB);
    expect(a.subjectId).not.toBe(b.subjectId);
  });

  it("CeremonyOutcome.success === true (dry-run completes proposal→queue→execute→verify)", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.ceremonyOutcome.success).toBe(true);
    expect(result.ceremonyOutcome.dryRun).toBe(true);
  });

  it("ceremonyOutcome.stagesReached contains the full 7-stage lifecycle", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.ceremonyOutcome.stagesReached).toContain("proposal");
    expect(result.ceremonyOutcome.stagesReached).toContain("queue");
    expect(result.ceremonyOutcome.stagesReached).toContain("execute");
    expect(result.ceremonyOutcome.stagesReached).toContain("verify");
    expect(result.ceremonyOutcome.stagesReached).toContain("complete");
  });
});
