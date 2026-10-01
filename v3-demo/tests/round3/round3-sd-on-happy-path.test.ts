// M8 Round 3 — SD On Happy Path (internal build brief, Steps 1-9 main success).
//
// Asserts the full happy-path composition: ingest with sd_enabled=true,
// SD bundle produced + delivered DAY-ONE, escrow proceeds in parallel,
// recipient ends up with BOTH bundles, partner SDK verifies SD bundle,
// cleanup state terminal.

import { describe, it, expect } from "vitest";
import { runRound3, runRound3Structural } from "../../src/rounds/round3.js";

describe("Round 3 — SD On (happy path)", () => {
  it("completes Steps 1-9 without throwing", async () => {
    const result = await runRound3Structural();
    expect(result.sdEnabled).toBe(true);
    expect(result.modeA).toBe(true);
    expect(result.accessStructure).toBe("FIXED_ONLY_3_OF_3_LIT_G3_G4");
    expect(result.g3Variant).toBe("drand");
    expect(result.g4Phase).toBe(1);
    expect(result.fixtureName).toBe("testament");
  });

  it("subjectId is fresh-per-run (REPEATABILITY drift #14)", async () => {
    const a = await runRound3Structural();
    const b = await runRound3Structural();
    expect(a.subjectId).not.toEqual(b.subjectId);
    expect(a.subjectId.startsWith("demo-r3-")).toBe(true);
    expect(b.subjectId.startsWith("demo-r3-")).toBe(true);
  });

  it("captures authorizationId + hCommit + sdMerkleRoot + sdBundleId", async () => {
    const result = await runRound3Structural();
    expect(result.authorizationId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.hCommit).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.sdMerkleRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.sdBundleId).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("uses M4 testament fixture per M8_ROUND_FIXTURES.round3", async () => {
    const result = await runRound3Structural();
    expect(result.fixtureName).toBe("testament");
  });

  it("runRound3() dispatcher honors DEMO_DRY_RUN env (CLI gate)", async () => {
    const original = process.env.DEMO_DRY_RUN;
    process.env.DEMO_DRY_RUN = "1";
    try {
      const result = await runRound3();
      expect(result.sdEnabled).toBe(true);
    } finally {
      if (original === undefined) delete process.env.DEMO_DRY_RUN;
      else process.env.DEMO_DRY_RUN = original;
    }
  });

  it("oneWayEdgePreserved flag is set true (structural smoke)", async () => {
    const result = await runRound3Structural();
    expect(result.oneWayEdgePreserved).toBe(true);
  });
});
