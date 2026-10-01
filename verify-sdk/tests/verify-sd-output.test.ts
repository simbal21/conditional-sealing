import { describe, expect, it } from "vitest";
import { verifySdOutput } from "../src/index.js";
import type { Hex32 } from "../src/types.js";

describe("verifySdOutput", () => {
  it("passes complete SD output with root and claims", async () => {
    const result = await verifySdOutput({
      status: "complete",
      authorizationId: hex(1),
      h_commit: hex(2),
      pda_root: hex(3),
      sdMerkleRoot: hex(4),
      claims: [{ type: "age_over_18" }],
    });
    expect(result.overall).toBe("pass");
    expect(result.checks.status?.status).toBe("pass");
  });

  it("fails failed SD output but keeps diagnostics structured", async () => {
    const result = await verifySdOutput({ status: "failed", h_commit: hex(2) });
    expect(result.overall).toBe("fail");
    expect(result.checks.status?.code).toBe("SD_STATUS.FAILED");
  });

  it("skips non-configured optional expiry and revocation checks", async () => {
    const result = await verifySdOutput({ status: "not_configured" });
    expect(result.overall).toBe("pass");
    expect(result.checks.status?.status).toBe("skipped");
    expect(result.checks.expiry?.status).toBe("skipped");
    expect(result.checks.revocation?.status).toBe("skipped");
  });

  it("covers malformed shape and optional online metadata branches", async () => {
    await expect(verifySdOutput({ status: "complete", h_commit: "0x123" })).resolves.toMatchObject({
      overall: "fail",
      checks: { shape: { code: "SD_SHAPE.H_COMMIT_MALFORMED" } },
    });
    await expect(verifySdOutput({ status: "complete", authorizationId: "0x123" })).resolves.toMatchObject({
      overall: "fail",
      checks: { shape: { code: "SD_SHAPE.AUTHORIZATION_ID_MALFORMED" } },
    });
    await expect(verifySdOutput({ status: "complete", pda_root: "0x123" })).resolves.toMatchObject({
      overall: "fail",
      checks: { shape: { code: "SD_SHAPE.PDA_ROOT_MALFORMED" } },
    });
    await expect(verifySdOutput({ status: "complete" })).resolves.toMatchObject({
      overall: "fail",
      checks: { status: { code: "SD_STATUS.COMPLETE_WITHOUT_OUTPUT" } },
    });
    await expect(
      verifySdOutput({ status: "partial_failure" }, { checkExpiry: true, checkRevocation: true }),
    ).resolves.toMatchObject({
      overall: "pass",
      checks: {
        status: { code: "SD_STATUS.PARTIAL_FAILURE_RECORDED" },
        expiry: { status: "pass" },
        revocation: { status: "pass" },
      },
    });
  });
});

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}
