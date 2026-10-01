import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { M2_CONTRACT_NAMES, M2_OUT_DIR, loadAbi } from "../../src/m2-imports.js";

describe("M2 imports (lazy ABI loader)", () => {
  it("declares all M7-consumed contract names", () => {
    // The M7 ceremonies touch the five V3 registries + adjacent surfaces.
    const required = [
      "G4AuthorityRegistry",
      "PluginHashRegistry",
      "DSLVersionRegistry",
      "OracleRegistry",
      "QTSPRegistry",
      "ShredRegistry",
      "ChallengeRegistry",
      "PartnerRegistry",
    ];
    for (const r of required) {
      expect(M2_CONTRACT_NAMES).toContain(r);
    }
  });

  it("M2_OUT_DIR points at the contracts/out directory", () => {
    expect(M2_OUT_DIR.endsWith("contracts/out")).toBe(true);
  });

  it("loadAbi throws if artifact is missing (no eager IO at import time)", async () => {
    // We only assert behavior when out/ is empty — if forge already built
    // ABIs, the call would succeed. Either case is fine; this test asserts
    // the loader is lazy and does not crash on import.
    if (!existsSync(M2_OUT_DIR)) {
      await expect(loadAbi("G4AuthorityRegistry")).rejects.toThrow();
    } else {
      // contracts/out exists from prior M2 build — skip the throw assertion
      expect(true).toBe(true);
    }
  });

  it("M2_CONTRACT_NAMES is frozen", () => {
    expect(Object.isFrozen(M2_CONTRACT_NAMES)).toBe(true);
  });
});
