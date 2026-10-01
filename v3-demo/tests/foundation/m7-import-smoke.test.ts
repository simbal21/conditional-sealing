import { describe, it, expect } from "vitest";
import * as M7 from "../../src/m7-imports.js";

describe("m7-imports smoke (M7 @cealis/v3-ops facade)", () => {
  it("re-exports the 4 round-critical ceremony classes", () => {
    expect(typeof M7.ShredTriggerCeremony).toBe("function");
    expect(typeof M7.PauseActivationCeremony).toBe("function");
    expect(typeof M7.PauseDeactivationCeremony).toBe("function");
  });

  it("re-exports the 4 registry-deprecation ceremonies for refusal codes 0x06-0x09", () => {
    expect(typeof M7.PluginVersionUpdateCeremony).toBe("function");
    expect(typeof M7.G4AuthorityRotationCeremony).toBe("function");
    expect(typeof M7.DslVersionUpdateCeremony).toBe("function");
    expect(typeof M7.OracleRotationCeremony).toBe("function");
  });

  it("REFUSAL_DEPRECATION_CEREMONY_MAP covers 0x06-0x09", () => {
    expect(M7.REFUSAL_DEPRECATION_CEREMONY_MAP[0x06]).toBe("PluginVersionUpdateCeremony");
    expect(M7.REFUSAL_DEPRECATION_CEREMONY_MAP[0x07]).toBe("G4AuthorityRotationCeremony");
    expect(M7.REFUSAL_DEPRECATION_CEREMONY_MAP[0x08]).toBe("DslVersionUpdateCeremony");
    expect(M7.REFUSAL_DEPRECATION_CEREMONY_MAP[0x09]).toBe("OracleRotationCeremony");
  });

  it("re-exports CEREMONY_CATALOG + V3 registry catalog", () => {
    expect(M7.CEREMONY_CATALOG).toBeDefined();
    expect(Array.isArray(M7.CEREMONY_CATALOG)).toBe(true);
    expect(M7.FIVE_V3_REGISTRIES).toBeDefined();
    expect(M7.FIVE_V3_REGISTRIES.length).toBe(5);
  });

  it("re-exports core Ceremony primitives", () => {
    expect(typeof M7.Ceremony).toBe("function");
    expect(typeof M7.makeContext).toBe("function");
    expect(typeof M7.generateCeremonyId).toBe("function");
    expect(typeof M7.proposalHash).toBe("function");
  });
});
