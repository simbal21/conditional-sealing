import { describe, it, expect } from "vitest";
import * as M2 from "../../src/m2-imports.js";

describe("m2-imports smoke (M2 ABIs loaded from contracts/out/)", () => {
  it("declares all 10 expected M2 contract names", () => {
    expect(M2.M2_CONTRACT_NAMES).toEqual([
      "ConditionEngine",
      "ShredRegistry",
      "ChallengeRegistry",
      "DisclosureRegistry",
      "DisclosureRevocationRegistry",
      "PluginHashRegistry",
      "G4AuthorityRegistry",
      "DSLVersionRegistry",
      "OracleRegistry",
      "QTSPRegistry",
    ]);
  });

  it("exposes a unique address env var per contract", () => {
    const envVars = Object.values(M2.M2_ADDRESS_ENV_VAR);
    expect(new Set(envVars).size).toBe(envVars.length);
    expect(envVars).toHaveLength(10);
  });

  it("loads all 10 ABIs from Foundry artifacts at module init", () => {
    for (const name of M2.M2_CONTRACT_NAMES) {
      const abi = M2.M2_ABIS[name];
      expect(abi).toBeDefined();
      expect(Array.isArray(abi)).toBe(true);
      expect(abi.length).toBeGreaterThan(0);
    }
  });

  it("ConditionEngine ABI exposes RevealAuthorized event (Round 2 absence-of-event target)", () => {
    const abi = M2.M2_ABIS.ConditionEngine;
    const revealEvent = abi.find(
      (item) =>
        (item as { type?: string }).type === "event" &&
        (item as { name?: string }).name === "RevealAuthorized",
    );
    expect(revealEvent).toBeDefined();
  });

  it("ShredRegistry ABI exposes ShredFinalized event (Round 2 shred-trigger target)", () => {
    const abi = M2.M2_ABIS.ShredRegistry;
    const shredEvent = abi.find(
      (item) =>
        (item as { type?: string }).type === "event" &&
        (item as { name?: string }).name === "ShredFinalized",
    );
    expect(shredEvent).toBeDefined();
  });

  it("M2_EVENT_NAMES catalog contains the round-critical events", () => {
    expect(M2.M2_EVENT_NAMES.RevealAuthorized).toBe("RevealAuthorized");
    expect(M2.M2_EVENT_NAMES.ShredFinalized).toBe("ShredFinalized");
  });

  it("readAddressFromEnv returns undefined when env unset", () => {
    // ConditionEngine address env intentionally not set in test environment.
    const prior = process.env.CONDITION_ENGINE_ADDRESS;
    delete process.env.CONDITION_ENGINE_ADDRESS;
    try {
      expect(M2.readAddressFromEnv("ConditionEngine")).toBeUndefined();
    } finally {
      if (prior !== undefined) process.env.CONDITION_ENGINE_ADDRESS = prior;
    }
  });
});
