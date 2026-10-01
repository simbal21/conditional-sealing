import { describe, it, expect } from "vitest";
import * as M4 from "../../src/m4-imports.js";

describe("m4-imports smoke (M4 @cealis/v3-configurator/fixtures facade)", () => {
  it("re-exports the 5 archetype submitted-PDA fixtures", () => {
    expect(M4.testamentSubmittedPda).toBeDefined();
    expect(M4.deadManSwitchSubmittedPda).toBeDefined();
    expect(M4.kycLendingSubmittedPda).toBeDefined();
    expect(M4.evidenceArchivalSubmittedPda).toBeDefined();
    expect(M4.mAndADealSubmittedPda).toBeDefined();
  });

  it("re-exports the 5 archetype spec objects", () => {
    expect(M4.testament).toBeDefined();
    expect(M4.deadManSwitch).toBeDefined();
    expect(M4.kycLending).toBeDefined();
    expect(M4.evidenceArchival).toBeDefined();
    expect(M4.mAndADeal).toBeDefined();
  });

  it("APP_A_FIXTURES enumerates all 5 archetypes", () => {
    expect(M4.APP_A_FIXTURES).toHaveLength(5);
    const names = M4.APP_A_FIXTURES.map((f: { name: string }) => f.name);
    expect(names).toEqual(
      expect.arrayContaining(["kyc-lending", "testament", "evidence-archival", "m-and-a-deal", "dead-man-switch"]),
    );
  });

  it("M8_ROUND_FIXTURES routes Round 1+2b+3 → testament, Round 2 → deadManSwitch", () => {
    expect(M4.M8_ROUND_FIXTURES.round1).toBe("testament");
    expect(M4.M8_ROUND_FIXTURES.round2).toBe("deadManSwitch");
    expect(M4.M8_ROUND_FIXTURES.round2b).toBe("testament");
    expect(M4.M8_ROUND_FIXTURES.round3).toBe("testament");
  });
});
