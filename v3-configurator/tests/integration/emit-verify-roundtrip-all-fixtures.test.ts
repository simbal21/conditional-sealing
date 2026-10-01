import { describe, expect, it } from "vitest";
import { APP_A_FIXTURES } from "../../fixtures/app-a/index.js";
import { emitPDA, validatePDA } from "../../src/pda/emit.js";
import { verifyPDAArtifact } from "../../src/pda/verify.js";

describe("Phase E emit/verify round-trip across App. A fixtures", () => {
  it.each(APP_A_FIXTURES)("$name validates, emits, and verifies", async ({ submitted }) => {
    const validation = validatePDA(submitted);
    expect(validation.ok).toBe(true);

    const artifact = await emitPDA(submitted);
    expect(artifact.pdaRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(artifact.contentHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(artifact.ipfs).toHaveLength(2);

    const verification = await verifyPDAArtifact(artifact);
    expect(verification.ok).toBe(true);
    expect(verification.mismatches).toEqual([]);
  });
});
