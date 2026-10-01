import { describe, expect, it } from "vitest";
import { kycLendingSubmittedPda } from "../../fixtures/app-a/index.js";
import { diffPDA } from "../../src/pda/index.js";

describe("§10.4 registry deprecation overlay in Phase E diff", () => {
  it("evaluates deprecation at authorization block", () => {
    const diff = diffPDA(kycLendingSubmittedPda, kycLendingSubmittedPda, {
      commitBlock: 100n,
      authorizationBlock: 102n,
      registryReferences: [{ registry: "OracleRegistry", entry_id: "oracle-a" }],
      deprecations: [
        { registry: "OracleRegistry", entry_id: "oracle-a", deprecated_at_block: 101n },
      ],
    });

    expect(diff.ok).toBe(false);
    expect(diff.registryOverlay.checked_at_block).toBe(102n);
    expect(diff.registryOverlay.halted).toBe(true);
    expect(diff.registryOverlay.affected_entries).toEqual(["OracleRegistry:oracle-a"]);
  });
});
