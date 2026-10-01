import { describe, expect, it } from "vitest";
import {
  evaluateRegistryDeprecationOverlay,
  runRegistryOverlayReplay,
} from "../../src/simulation/index.js";

describe("§10.4 registry deprecation overlay", () => {
  it("checks registry deprecation at authorization block, not frozen commit block", () => {
    const input = {
      pda_root_commit_block: 100n,
      authorization_block: 102n,
      referenced_entries: [
        { registry: "OracleRegistry", entry_id: "oracle-a" },
      ],
      deprecations: [
        {
          registry: "OracleRegistry",
          entry_id: "oracle-a",
          deprecated_at_block: 101n,
        },
      ],
    };

    const overlay = evaluateRegistryDeprecationOverlay(input);
    const step = runRegistryOverlayReplay(input);

    expect(overlay.checked_at_block).toBe(102n);
    expect(overlay.halted).toBe(true);
    expect(overlay.affected_entries).toEqual(["OracleRegistry:oracle-a"]);
    expect(step.ok).toBe(false);
    expect(step.details).toContain("halts authorization at block 102");
  });
});
