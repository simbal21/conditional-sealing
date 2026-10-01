import { describe, expect, it } from "vitest";
import { kycLendingSubmittedPda } from "../../fixtures/app-a/index.js";
import { diffPDA } from "../../src/pda/index.js";
import { hashToHex32 } from "../../src/pda/pda-root.js";

describe("§10.6 supersession discipline", () => {
  it("rejects frozen template-id mutation without supersession", () => {
    const after = {
      ...kycLendingSubmittedPda,
      template_id: hashToHex32("patched-template"),
    };
    const diff = diffPDA(kycLendingSubmittedPda, after);
    expect(diff.ok).toBe(false);
    expect(diff.changes.some((change) => change.path === "template_id" && change.kind === "forbidden")).toBe(true);
  });
});
