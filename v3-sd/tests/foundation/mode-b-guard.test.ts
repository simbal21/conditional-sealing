// Foundation test — §14 Mode B two-branch coverage (PHASE-PLAN §0 item #4).
//
// Branch 1 (ACCEPT): MODE_B + sd_enabled=false → no error.
// Branch 2 (REJECT): MODE_B + sd_enabled=true  → ERR_SD_CONFIG_MODE_B_INCOMPATIBLE.
// Branch 3 (ACCEPT): MODE_A + sd_enabled=true  → no error.
// Branch 4 (ACCEPT): MODE_A + sd_enabled=false → no error.

import { describe, it, expect } from "vitest";
import { assertModeBSdCompatible } from "../../src/mode-b/rejection.js";
import { SdError } from "../../src/errors/sd-error.js";
import { SdErrorCode } from "../../src/errors/codes.js";

describe("§14 Mode B + SD guard — two-branch coverage", () => {
  it("Branch 1: MODE_B + sd_enabled=false → silent accept (§14.2 line 1187)", () => {
    expect(() => assertModeBSdCompatible({ ingestion_mode: "MODE_B", sd_enabled: false })).not.toThrow();
  });

  it("Branch 2: MODE_B + sd_enabled=true → ERR_SD_CONFIG_MODE_B_INCOMPATIBLE (§14.2 line 1182)", () => {
    expect(() => assertModeBSdCompatible({ ingestion_mode: "MODE_B", sd_enabled: true })).toThrow();
    try {
      assertModeBSdCompatible({ ingestion_mode: "MODE_B", sd_enabled: true });
    } catch (e) {
      expect(e).toBeInstanceOf(SdError);
      expect((e as SdError).code).toBe(SdErrorCode.CONFIG_MODE_B_INCOMPATIBLE);
    }
  });

  it("Branch 3: MODE_A + sd_enabled=true → silent accept", () => {
    expect(() => assertModeBSdCompatible({ ingestion_mode: "MODE_A", sd_enabled: true })).not.toThrow();
  });

  it("Branch 4: MODE_A + sd_enabled=false → silent accept", () => {
    expect(() => assertModeBSdCompatible({ ingestion_mode: "MODE_A", sd_enabled: false })).not.toThrow();
  });

  it("error payload includes correlationId in safeRefs when supplied", () => {
    try {
      assertModeBSdCompatible({ ingestion_mode: "MODE_B", sd_enabled: true, correlationId: "test-corr-123" });
    } catch (e) {
      expect(e).toBeInstanceOf(SdError);
      expect((e as SdError).correlationId).toBe("test-corr-123");
    }
  });
});
