// Phase E E2 — Mode B + SD defense-in-depth (S2-7 §14.2 NORMATIVE).
//
// 3 INDEPENDENT REJECTION SURFACES tested:
//   Case A: M5 path rejects MODE_B + sd_enabled=true (HttpProblem
//           code = SCHEMA.MODE_B_RESERVED).
//   Case B: M6 module rejects MODE_B + sd_enabled=true (SdError
//           code = ERR_SD_CONFIG_MODE_B_INCOMPATIBLE) independently.
//   Case C: M5 rejects bare MODE_B (sd_enabled=false) — reserved-mode at the
//           live ingestion endpoint regardless of SD configuration.
//
// All three MUST independently reject. Defense-in-depth means EITHER
// surface alone CAN catch the misconfig; both should because neither layer
// trusts the other.

import { describe, it, expect } from "vitest";
import {
  runE2,
  runCaseAM5Rejects,
  runCaseBM6Rejects,
  runCaseCBareModeBRejects,
} from "../../src/cross-round/mode-b-defense-in-depth.js";

describe("Phase E2 — Mode B + SD defense-in-depth (S2-7 §14.2 NORMATIVE)", () => {
  it("Case A: M5 rejects MODE_B + sd_enabled=true via HttpProblem", async () => {
    const outcome = await runCaseAM5Rejects();
    expect(outcome.rejected).toBe(true);
    expect(outcome.errorCategory).toBe("HttpProblem");
    expect(outcome.errorCode).toBe("SCHEMA.MODE_B_RESERVED");
    // Document upstream actual status (brief expected 400; upstream is 409).
    expect(outcome.httpStatus).toBe(409);
  });

  it("Case B: M6 module rejects MODE_B + sd_enabled=true independently via SdError", () => {
    const outcome = runCaseBM6Rejects();
    expect(outcome.rejected).toBe(true);
    expect(outcome.errorCategory).toBe("SdError");
    expect(outcome.errorCode).toBe("ERR_SD_CONFIG_MODE_B_INCOMPATIBLE");
  });

  it("Case C: M5 rejects bare MODE_B (sd_enabled=false) at the live endpoint", async () => {
    const outcome = await runCaseCBareModeBRejects();
    expect(outcome.rejected).toBe(true);
    expect(outcome.errorCategory).toBe("HttpProblem");
    expect(outcome.errorCode).toBe("SCHEMA.MODE_B_RESERVED");
    expect(outcome.httpStatus).toBe(409);
  });

  it("runE2 confirms ALL THREE layers reject independently", async () => {
    const outcome = await runE2();
    expect(outcome.allThreeIndependentlyRejected).toBe(true);
    expect(outcome.caseA.rejected).toBe(true);
    expect(outcome.caseB.rejected).toBe(true);
    expect(outcome.caseC.rejected).toBe(true);
  });

  it("Case A and Case C use the SAME error code (SCHEMA.MODE_B_RESERVED)", async () => {
    // The brief sometimes distinguishes these as different codes; upstream
    // M5 consolidates both under SCHEMA.MODE_B_RESERVED. Confirm.
    const a = await runCaseAM5Rejects();
    const c = await runCaseCBareModeBRejects();
    expect(a.errorCode).toBe(c.errorCode);
  });

  it("Case B's error code is DISTINCT from cases A/C (different layer)", async () => {
    const a = await runCaseAM5Rejects();
    const b = runCaseBM6Rejects();
    expect(b.errorCode).not.toBe(a.errorCode);
    // M6 surface owns ERR_SD_*; M5 surface owns SCHEMA.*.
    expect(b.errorCode.startsWith("ERR_SD_")).toBe(true);
    expect(a.errorCode.startsWith("SCHEMA.")).toBe(true);
  });
});
