import { describe, expect, it } from "vitest";
import { buildSdPlan } from "../../src/sd-plan/build.js";
import { b32 } from "./helpers.js";

describe("sd_plan_digest determinism (SD-CFG-005)", () => {
  it("same PDA input with different JSON key ordering produces identical digest", () => {
    const a = buildSdPlan({
      pda_config: { sd_enabled: true, ingestion_mode: "MODE_A", pda_id: b32("pda"), pda_version: 1n },
      partner_id: b32("partner"),
      schema: { fields: [{ path: "x", type: "uint", numeric_bit_width: 16, nullable: false }] },
    });
    const b = buildSdPlan({
      pda_config: { pda_version: 1n, pda_id: b32("pda"), ingestion_mode: "MODE_A", sd_enabled: true },
      partner_id: b32("partner"),
      schema: { fields: [{ nullable: false, numeric_bit_width: 16, type: "uint", path: "x" }] },
    });
    expect(Buffer.from(a.sd_plan_digest).toString("hex")).toBe(Buffer.from(b.sd_plan_digest).toString("hex"));
  });
});
