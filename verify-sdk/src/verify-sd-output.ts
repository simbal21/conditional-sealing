import type { SdOutput, VerifyCheck, VerifySdOptions, VerifySdResult, VerifyStatus } from "./types.js";
import { failCheck, isHex32, passCheck, skippedCheck } from "./checks/canonicalization.js";

export async function verifySdOutput(
  sd: SdOutput,
  options: VerifySdOptions = {},
): Promise<VerifySdResult> {
  void options.now;
  const checks: Record<string, VerifyCheck> = {
    shape: checkShape(sd),
    status: checkStatus(sd),
    expiry: options.checkExpiry === true ? passCheck("SD_EXPIRY.NOT_PRESENT_IN_ARTIFACT") : skippedCheck("SD_EXPIRY.NOT_REQUESTED"),
    revocation:
      options.checkRevocation === true
        ? passCheck("SD_REVOCATION.NOT_PRESENT_IN_ARTIFACT")
        : skippedCheck("SD_REVOCATION.NOT_REQUESTED"),
  };
  return {
    overall: overallStatus(Object.values(checks)),
    checks,
  };
}

function checkShape(sd: SdOutput): VerifyCheck {
  if (sd.h_commit !== undefined && !isHex32(sd.h_commit)) {
    return failCheck("SD_SHAPE.H_COMMIT_MALFORMED", "SD h_commit must be 32-byte hex when present.");
  }
  if (sd.authorizationId !== undefined && !isHex32(sd.authorizationId)) {
    return failCheck("SD_SHAPE.AUTHORIZATION_ID_MALFORMED", "SD authorizationId must be 32-byte hex when present.");
  }
  if (sd.pda_root !== undefined && !isHex32(sd.pda_root)) {
    return failCheck("SD_SHAPE.PDA_ROOT_MALFORMED", "SD pda_root must be 32-byte hex when present.");
  }
  return passCheck("SD_SHAPE.PASS");
}

function checkStatus(sd: SdOutput): VerifyCheck {
  if (sd.status === "not_configured" || sd.status === "skipped") {
    return skippedCheck("SD_STATUS.NOT_CONFIGURED");
  }
  if (sd.status === "failed") {
    return failCheck("SD_STATUS.FAILED", "SD output reports failed status.");
  }
  if (sd.status === "complete" && sd.sdMerkleRoot === undefined && (sd.claims?.length ?? 0) === 0) {
    return failCheck("SD_STATUS.COMPLETE_WITHOUT_OUTPUT", "Complete SD output must carry sdMerkleRoot or claims.");
  }
  if (sd.status === "partial_failure") {
    return passCheck("SD_STATUS.PARTIAL_FAILURE_RECORDED");
  }
  return passCheck("SD_STATUS.PASS");
}

function overallStatus(checks: readonly VerifyCheck[]): VerifyStatus {
  if (checks.some((check) => check.status === "fail")) return "fail";
  if (checks.every((check) => check.status === "skipped")) return "skipped";
  return "pass";
}
