import { describe, expect, it } from "vitest";
import { buildSdPlan } from "../../src/sd-plan/build.js";
import { SdError } from "../../src/errors/sd-error.js";
import { SdErrorCode } from "../../src/errors/codes.js";
import { b32 } from "./helpers.js";

describe("Mode B SD rejection E2E", () => {
  it("rejects Mode B + SD enabled before proof generation", () => {
    expect(() => buildSdPlan({
      pda_config: { sd_enabled: true, ingestion_mode: "MODE_B", pda_id: b32("pda"), pda_version: 1n },
      partner_id: b32("partner"),
      schema: { fields: [{ path: "x", type: "uint", numeric_bit_width: 16 }] },
    })).toThrow(SdError);
    try {
      buildSdPlan({
        pda_config: { sd_enabled: true, ingestion_mode: "MODE_B", pda_id: b32("pda"), pda_version: 1n },
        partner_id: b32("partner"),
        schema: { fields: [{ path: "x", type: "uint", numeric_bit_width: 16 }] },
      });
    } catch (error) {
      expect((error as SdError).code).toBe(SdErrorCode.CONFIG_MODE_B_INCOMPATIBLE);
    }
  });
});

