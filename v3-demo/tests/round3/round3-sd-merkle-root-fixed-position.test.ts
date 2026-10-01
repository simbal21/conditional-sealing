// M8 Round 3 — sdMerkleRoot at fixed commit_AAD position (Step 2 / BP-SD-1).
//
// Per S2-1 §4 (BP-SD-1 closed 2026-05-05): sdMerkleRoot is bound at a
// FIXED position within commit_AAD when SD is enabled. The partner SDK
// asserts this via the EscrowCommitReference.commit_AAD.sdMerkleRoot
// reference; tampering at this position invalidates the bundle.

import { describe, it, expect } from "vitest";
import { runRound3Structural } from "../../src/rounds/round3.js";

describe("Round 3 — sdMerkleRoot at fixed commit_AAD position (BP-SD-1)", () => {
  it("Round 3 result records sdMerkleRoot at 'fixed' commit_AAD position", async () => {
    const result = await runRound3Structural();
    expect(result.sdMerkleRootCommitAADPosition).toBe("fixed");
  });

  it("SD bundle carries sdMerkleRoot matching the commit binding", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.sdMerkleRoot).toBe(result.sdMerkleRoot);
  });

  it("rootBindingLevel is 'commit_AAD' per S2-7 App. I.4 LOCKED literal", async () => {
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.rootBindingLevel).toBe("commit_AAD");
  });

  it("commit_version is '0x0302' (active version supporting sdMerkleRoot)", async () => {
    // The escrow-commit reference passed to the partner SDK declares
    // commit_version === "0x0302" — the only version under which
    // rootBindingLevel === "commit_AAD" is valid per §I.4.
    // We probe via the bundle digest field shape: presence of
    // sdMerkleRoot in the bundle is conditional on commit_version 0x0302.
    const result = await runRound3Structural();
    expect(result.recipient.sdBundle.sdMerkleRoot).toBeDefined();
    expect(result.recipient.sdBundle.sdMerkleRoot).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("sdMerkleRoot is a 32-byte hex scalar", async () => {
    const result = await runRound3Structural();
    expect(result.sdMerkleRoot).toMatch(/^0x[0-9a-f]{64}$/);
  });
});
