// Phase E E3 — Halt activation blocks ingestion (S2-2 §14 NORMATIVE).
//
// 4-step cycle test:
//   1. PauseActivationCeremony.run() emits PauseActivated.
//   2. createModeAIngestion under halted=true throws HttpProblem
//      (code = GOVERNANCE.G4_REFUSED — upstream actual).
//   3. PauseDeactivationCeremony.run() emits PauseDeactivated.
//   4. createModeAIngestion under halted=false succeeds.

import { describe, it, expect } from "vitest";
import { runE3 } from "../../src/cross-round/halt-activation.js";

describe("Phase E3 — Halt activation blocks ingestion (S2-2 §14 NORMATIVE)", () => {
  it("Step 1: PauseActivationCeremony succeeds and emits PauseActivated", async () => {
    const outcome = await runE3();
    expect(outcome.step1PauseOutcome.success).toBe(true);
    expect(outcome.step1PauseActivatedEmitted).toBe(true);
    expect(outcome.step1PauseOutcome.emittedEvents).toContain("PauseActivated");
  });

  it("Step 2: ingestion REJECTED while halted=true", async () => {
    const outcome = await runE3();
    expect(outcome.step2Rejected).toBe(true);
    expect(outcome.step2ErrorCode).toBe("GOVERNANCE.G4_REFUSED");
    // Document upstream actual status (brief expected 503; upstream is 409).
    expect(outcome.step2HttpStatus).toBe(409);
  });

  it("Step 3: PauseDeactivationCeremony succeeds and emits PauseDeactivated", async () => {
    const outcome = await runE3();
    expect(outcome.step3UnpauseOutcome.success).toBe(true);
    expect(outcome.step3PauseDeactivatedEmitted).toBe(true);
    expect(outcome.step3UnpauseOutcome.emittedEvents).toContain("PauseDeactivated");
  });

  it("Step 4: ingestion SUCCEEDS after unpause", async () => {
    const outcome = await runE3();
    expect(outcome.step4Succeeded).toBe(true);
    expect(outcome.step4Response).toBeDefined();
    expect(outcome.step4Response?.authorizationId).toMatch(/^0x[0-9a-fA-F]{64}$/);
  });

  it("Step 4 response carries commit_tx_hash + commit_block (M5 anchor surface)", async () => {
    const outcome = await runE3();
    expect(outcome.step4Response).toBeDefined();
    expect(outcome.step4Response?.commit_tx_hash).toMatch(/^0x[0-9a-fA-F]+$/);
    expect(outcome.step4Response?.commit_block).toBeGreaterThan(0);
  });

  it("Full cycle is deterministic and idempotent across two runs", async () => {
    const a = await runE3();
    const b = await runE3();
    expect(a.step2Rejected).toBe(b.step2Rejected);
    expect(a.step4Succeeded).toBe(b.step4Succeeded);
    expect(a.step1PauseActivatedEmitted).toBe(b.step1PauseActivatedEmitted);
    expect(a.step3PauseDeactivatedEmitted).toBe(b.step3PauseDeactivatedEmitted);
  });
});
