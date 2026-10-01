// M8 Round 3 — Recipient receives BOTH bundles (Step 7).
//
// After parallel-pipeline execution, the recipient holds both:
//   1. SD bundle (received at T=0, DAY-ONE delivery)
//   2. Escrow bundle (received at T+24h, after TimeLock fire)
//
// Both bundles are independently verifiable. Tampering one does not
// invalidate the other (asymmetric isolation per S2-7 §15).

import { describe, it, expect } from "vitest";
import { runRound3Structural } from "../../src/rounds/round3.js";

describe("Round 3 — Recipient receives BOTH bundles", () => {
  it("recipient has SD bundle attached", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle).toBeDefined();
    expect(result.recipient.sdBundle.sd_version).toBe("s2-7-1.0");
  });

  it("recipient has escrow bundle attached", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.escrowBundle).toBeDefined();
    expect(result.recipient.escrowBundle.status).toBe("delivered");
  });

  it("SD bundle has 'complete' status (happy path)", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.status).toBe("complete");
  });

  it("SD bundle contains at least one cleartext item + claim", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.cleartext.length).toBeGreaterThanOrEqual(1);
    expect(result.recipient.sdBundle.claims.length).toBeGreaterThanOrEqual(1);
  });

  it("SD bundle failures array is empty in happy path", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.failures).toEqual([]);
  });

  it("both bundles reference the SAME h_commit", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.h_commit).toEqual(result.recipient.escrowBundle.hCommit);
    expect(result.recipient.sdBundle.h_commit).toEqual(result.hCommit);
  });

  it("SD bundle exposes authorizationId binding the escrow commit", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.authorizationId).toEqual(result.authorizationId);
  });
});
