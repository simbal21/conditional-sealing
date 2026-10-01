import { describe, it, expect } from "vitest";
import {
  FIVE_V3_REGISTRIES,
  ADJACENT_REGISTRY_SURFACES,
  isV3Registry,
} from "../../src/catalog/registries.js";
import { V3_REGISTRY_METADATA } from "../../src/registry/v3-registries.js";

/**
 * Drift catch #8: Five Cealis-governed V3 registries (S2-6 §2 line 147 +
 * §13.6).
 */
describe("FIVE_V3_REGISTRIES (S2-6 §2 + §13.6)", () => {
  it("has exactly 5 entries", () => {
    expect(FIVE_V3_REGISTRIES).toHaveLength(5);
  });

  it("matches the verbatim §2 line 147 list", () => {
    expect([...FIVE_V3_REGISTRIES].sort()).toEqual(
      [
        "PluginHashRegistry",
        "G4AuthorityRegistry",
        "DSLVersionRegistry",
        "OracleRegistry",
        "QTSPRegistry",
      ].sort(),
    );
  });

  it("none of the adjacent surfaces are members of the 5", () => {
    for (const adj of ADJACENT_REGISTRY_SURFACES) {
      expect(isV3Registry(adj)).toBe(false);
    }
  });

  it("every member of the 5 has metadata entry", () => {
    for (const r of FIVE_V3_REGISTRIES) {
      expect(V3_REGISTRY_METADATA[r]).toBeDefined();
      expect(V3_REGISTRY_METADATA[r].specSection.length).toBeGreaterThan(0);
    }
  });

  it("type-guard rejects adjacent surfaces", () => {
    expect(isV3Registry("OracleSchemaRegistry")).toBe(false);
    expect(isV3Registry("ShredRegistry")).toBe(false);
    expect(isV3Registry("ChallengeRegistry")).toBe(false);
    expect(isV3Registry("PluginHashRegistry")).toBe(true);
  });
});
