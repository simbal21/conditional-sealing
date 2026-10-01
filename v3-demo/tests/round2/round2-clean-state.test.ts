// Step 9 — repeatability cleanup verifier.
//
// `assertCleanState` is a Phase A primitive that queries vault rows /
// BullMQ pending / chain Authorization state for the run's subjectId.
// Round 2 must leave NO orphan state after a successful run.
//
// Round 2 dry-run mode does not connect to real Postgres / Redis / chain
// — the cleanup verifier requires real infra. This test asserts the
// round result carries the data needed to drive the verifier (subjectId,
// hCommit, terminal shred state). Phase F live-mode runs assertCleanState
// against real infra.

import { describe, it, expect } from "vitest";
import {
  runRound2,
  makeDefaultRound2Dependencies,
  type Round2ContractAddresses,
} from "../../src/rounds/round2.js";

const ADDRESSES: Round2ContractAddresses = {
  conditionEngine: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  shredRegistry: "0xcccccccccccccccccccccccccccccccccccccccc",
};

describe("Round 2 — repeatability cleanup (Step 9)", () => {
  it("Result carries subjectId + hCommit + terminal Shredded state for cleanup verifier", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(result.subjectId).toMatch(/^demo-r2-/);
    expect(result.hCommit.length).toBe(2 + 64);
    expect(result.chainState.currentShredState).toBe("Shredded");
  });

  it("Multiple runs share no subjectId — fresh per run (repeatability)", async () => {
    const subjects = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
      const result = await runRound2(deps);
      subjects.add(result.subjectId);
    }
    expect(subjects.size).toBe(5);
  });

  it("Combiner spy reset between runs (clean-state precondition)", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    await runRound2(deps);
    expect(deps.combinerSpy.invocationCount).toBe(0);
    deps.combinerSpy.reset();
    expect(deps.combinerSpy.invocationCount).toBe(0);
  });

  it("G4 Phase 1 mock state reset between runs (clean-state precondition)", async () => {
    const deps = makeDefaultRound2Dependencies({ addresses: ADDRESSES });
    const result = await runRound2(deps);
    expect(deps.g4Phase1Mock.isShredded(result.hCommit)).toBe(true);
    deps.g4Phase1Mock.reset();
    expect(deps.g4Phase1Mock.isShredded(result.hCommit)).toBe(false);
  });
});
