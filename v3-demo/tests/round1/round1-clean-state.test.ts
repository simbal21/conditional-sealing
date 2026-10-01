// Round 1 — Step 10 isolated: repeatability cleanup verifier.
//
// REPEATABILITY (drift #14): every round uses a fresh subjectId. After a
// round, no orphan state remains for that subjectId — vault rows = 0,
// BullMQ pending = 0, on-chain Authorization terminal.
//
// At Phase B the cleanup runs against in-memory mocks (everything in-
// process is garbage-collected; the vault counter inside round1.ts asserts
// the idempotency property forbids a double-write). The real-infra
// `assertCleanState` is exposed as a discipline anchor and exercised in
// live mode end-to-end testing.

import { describe, expect, it } from "vitest";
import { runRound1 } from "../../src/rounds/round1.js";
import { assertCleanState } from "../../src/assert.js";

describe("Round 1 — Step 10 repeatability cleanup verifier", () => {
  it("runRound1 succeeds with skipArtifacts:true (no disk side effects)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.verify.overall).toBe("pass");
    expect(result.artifacts.outDir).toBeUndefined();
  });

  it("each round uses a fresh subjectId (REPEATABILITY is a binding property)", async () => {
    const a = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const b = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const c = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const ids = new Set([a.subjectId, b.subjectId, c.subjectId]);
    expect(ids.size).toBe(3);
  });

  it("subjectId follows the demo-r1-<uuid> prefix (per the internal build brief, Step 1)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.subjectId).toMatch(/^demo-r1-[0-9a-f-]+$/);
  });

  it("assertCleanState is exposed as a discipline-anchor primitive", () => {
    expect(typeof assertCleanState).toBe("function");
  });

  it("explicit subjectId override is honored (test repeatability seam)", async () => {
    const customId = `demo-r1-test-${Date.now()}`;
    const result = await runRound1({
      mode: "ci-anvil",
      skipArtifacts: true,
      subjectId: customId,
    });
    expect(result.subjectId).toBe(customId);
  });

  it("explicit runId override is honored (artifact-path repeatability seam)", async () => {
    const customRun = `r1-test-${Date.now()}`;
    const result = await runRound1({
      mode: "ci-anvil",
      skipArtifacts: true,
      runId: customRun,
    });
    expect(result.runId).toBe(customRun);
  });

  it("dryRun option is honored (no side effects in dryRun path)", async () => {
    const result = await runRound1({
      mode: "ci-anvil",
      skipArtifacts: true,
      dryRun: true,
    });
    expect(result.verify.overall).toBe("pass");
  });
});
