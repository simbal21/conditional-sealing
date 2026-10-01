// Phase E E1 — 7-stage asymmetric isolation table (S2-7 §15.2 NORMATIVE).
//
// Parameterized over `SD_FAILURE_STAGES`. For each row:
//   (a) escrow result preserved (NORMATIVE — §15.1 invariant)
//   (b) SD reports stage-specific failure outcome
//   (c) stage discriminator matches expected stage
//
// Single-failure-mode tests are explicitly NON-conformant per §15.2.

import { describe, it, expect } from "vitest";
import {
  runE1,
  runIsolationRow,
  ISOLATION_TABLE,
  SD_FAILURE_STAGES,
  type IsolationRowOutcome,
} from "../../src/cross-round/isolation-7-stage.js";

describe("Phase E1 — 7-stage asymmetric isolation table (S2-7 §15.2 NORMATIVE)", () => {
  it("table has exactly 7 rows matching SD_FAILURE_STAGES order", () => {
    expect(ISOLATION_TABLE).toHaveLength(7);
    expect(SD_FAILURE_STAGES).toHaveLength(7);
    expect(ISOLATION_TABLE.map((r) => r.stage)).toEqual([...SD_FAILURE_STAGES]);
  });

  it("runE1 returns 7 outcomes — one per stage", async () => {
    const outcomes = await runE1();
    expect(outcomes).toHaveLength(7);
  });

  describe("Per-row assertions — escrow preserved + SD fails at expected stage", () => {
    for (const row of ISOLATION_TABLE) {
      it(`stage=${row.stage}: escrow preserved + SD reports ${row.expectedSdCode}`, async () => {
        const outcome = await runIsolationRow(row);
        expect(outcome.escrowPreserved).toBe(true);
        expect(outcome.sdFailedAtExpectedStage).toBe(true);
        expect(outcome.escrow.kind).toBe("ok");
        if (outcome.escrow.kind === "ok") {
          expect(outcome.escrow.value.chainAnchorCommitted).toBe(true);
          expect(outcome.escrow.value.subjectId).toContain(row.stage);
        }
        expect(outcome.sd.kind).toBe("sd_err");
        if (outcome.sd.kind === "sd_err") {
          expect(outcome.sd.stage).toBe(row.stage);
          expect(outcome.sd.code).toBe(row.expectedSdCode);
        }
      });
    }
  });

  it("every row's escrow.kind === 'ok' (NORMATIVE §15.1 invariant)", async () => {
    const outcomes = await runE1();
    for (const outcome of outcomes) {
      expect(outcome.escrow.kind).toBe("ok");
    }
  });

  it("every row's sd.kind === 'sd_err' (the failure injection landed)", async () => {
    const outcomes = await runE1();
    for (const outcome of outcomes) {
      expect(outcome.sd.kind).toBe("sd_err");
    }
  });

  it("each stage appears in exactly one row (no duplicates)", () => {
    const stages = new Set(ISOLATION_TABLE.map((r) => r.stage));
    expect(stages.size).toBe(7);
  });

  it("response_assembly row carries partial=true (S2-7 §15.2 row 5)", async () => {
    const row = ISOLATION_TABLE.find((r) => r.stage === "response_assembly")!;
    const outcome = await runIsolationRow(row);
    expect(outcome.sd.kind).toBe("sd_err");
    if (outcome.sd.kind === "sd_err") {
      expect(outcome.sd.partial).toBe(true);
    }
  });

  it("non-response-assembly rows carry partial=false", async () => {
    const outcomes = await runE1();
    for (const outcome of outcomes) {
      if (outcome.sd.kind === "sd_err" && outcome.stage !== "response_assembly") {
        expect(outcome.sd.partial).toBe(false);
      }
    }
  });

  it("escrow value contains subjectId, authorizationId, hCommit, pdaRoot, vaultRef", async () => {
    const row = ISOLATION_TABLE[0]!;
    const outcome: IsolationRowOutcome = await runIsolationRow(row);
    expect(outcome.escrow.kind).toBe("ok");
    if (outcome.escrow.kind === "ok") {
      expect(outcome.escrow.value.authorizationId).toMatch(/^0x[0-9a-f]{64}$/);
      expect(outcome.escrow.value.hCommit).toMatch(/^0x[0-9a-f]{64}$/);
      expect(outcome.escrow.value.pdaRoot).toMatch(/^0x[0-9a-f]{64}$/);
      expect(outcome.escrow.value.vaultRef).toContain("vault://e1/");
    }
  });
});
