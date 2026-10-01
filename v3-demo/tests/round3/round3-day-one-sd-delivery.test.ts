// M8 Round 3 — DAY-ONE SD delivery (internal build brief, Step 3).
//
// NORMATIVE per S2-7 §1.5 + §15: SD bundle is delivered to recipient
// IMMEDIATELY at onboarding (T=0), NOT at TimeLock fire (T+24h CI sim).
// Escrow bundle is delivered ONLY after TimeLock fires.
//
// This test verifies the parallel-pipeline timing is distinct — the SD
// delivery timestamp precedes the escrow delivery timestamp by a gap > 0.
// In CI structural mode the gap is small (~50ms sleep); the test asserts
// the structural ordering, not real wall-clock 24h.

import { describe, it, expect } from "vitest";
import { runRound3Structural } from "../../src/rounds/round3.js";

describe("Round 3 — DAY-ONE SD delivery (parallel pipeline timing)", () => {
  it("SD bundle delivery timestamp precedes escrow bundle delivery", async () => {
    const result = await runRound3Structural();
    expect(result.timeline.tSDms).toBeLessThan(result.timeline.tEscrowMs);
  });

  it("timeline gap is strictly positive (DAY-ONE is distinct from escrow)", async () => {
    const result = await runRound3Structural();
    expect(result.timeline.gapMs).toBeGreaterThan(0);
  });

  it("timeline records CI timelock delay (86400s)", async () => {
    const result = await runRound3Structural();
    // Structural mode defaults to ci-anvil delay
    expect(result.timeline.timelockDelaySec).toBe(86400);
  });

  it("timeline.tSDms and timeline.tEscrowMs are valid epoch ms numbers", async () => {
    const result = await runRound3Structural();
    expect(Number.isFinite(result.timeline.tSDms)).toBe(true);
    expect(Number.isFinite(result.timeline.tEscrowMs)).toBe(true);
    expect(result.timeline.tSDms).toBeGreaterThan(0);
    expect(result.timeline.tEscrowMs).toBeGreaterThan(0);
  });

  it("recipient holds SD bundle independently of escrow bundle", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle).toBeDefined();
    expect(result.recipient.escrowBundle).toBeDefined();
    // SD bundle and escrow bundle carry SAME hCommit (per spec) but are
    // structurally distinct deliveries. The hCommit appears in BOTH.
    expect(result.recipient.sdBundle.h_commit).toEqual(result.hCommit);
    expect(result.recipient.escrowBundle.hCommit).toEqual(result.hCommit);
  });

  it("gap is consistent under repeated runs (sleep-based, NOT race-prone)", async () => {
    // The 50ms structural sleep is deterministic-enough that 5 runs all
    // produce positive gaps. Flake-guard: if any run has gap <= 0 it's a
    // regression in the timeline capture order.
    for (let i = 0; i < 5; i++) {
      const result = await runRound3Structural();
      expect(result.timeline.gapMs).toBeGreaterThan(0);
    }
  });
});
