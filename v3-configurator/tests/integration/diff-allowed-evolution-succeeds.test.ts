import { describe, expect, it } from "vitest";
import { deadManSwitchSubmittedPda } from "../../fixtures/app-a/index.js";
import { diffPDA } from "../../src/pda/index.js";

describe("§10 PDA evolution diff", () => {
  it("allows mutable long-TTL update paths when pda_updatable is true", () => {
    const after = {
      ...deadManSwitchSubmittedPda,
      retention_seconds: 1_000_000_000,
    };
    const diff = diffPDA(deadManSwitchSubmittedPda, after);
    expect(diff.ok).toBe(true);
    expect(diff.changes.map((change) => change.path)).toContain("retention_seconds");
  });
});
