import { describe, expect, it } from "vitest";
import { buildSdPlan } from "../../src/sd-plan/build.js";
import { executeSdAtCommit } from "../../src/sd-plan/execute.js";
import { SdError } from "../../src/errors/sd-error.js";
import { SdErrorCode } from "../../src/errors/codes.js";
import { createM5IngestionStub } from "../../src/__tests__/m5-stub.js";
import { b32, baseSchema, dek, payload } from "./helpers.js";

describe("Mode B + SD two-branch discipline", () => {
  it("accepts MODE_B with sd_enabled=false and returns not_configured while escrow proceeds", async () => {
    const stub = createM5IngestionStub();
    const escrow = await stub.execute({
      authorizationId: b32("auth-b-accept"),
      pda_id: b32("pda"),
      pda_version: 1n,
      schema_digest: b32("schema"),
      partner_id: b32("partner"),
      ingestion_mode: "MODE_B",
      plaintext: payload(),
      dek: dek(),
    });
    expect(escrow.kind).toBe("ok");

    const plan = buildSdPlan({
      pda_config: { sd_enabled: false, ingestion_mode: "MODE_B", pda_id: b32("pda"), pda_version: 1n },
      partner_id: b32("partner"),
      schema: baseSchema,
    });
    const result = await executeSdAtCommit({
      plaintext: payload(),
      plan,
      dek: dek(),
      commit_ctx: {
        authorizationId: b32("auth-b-accept"),
        h_commit: escrow.kind === "ok" ? escrow.h_commit : b32("never"),
        pda_root: escrow.kind === "ok" ? escrow.pda_root : b32("never"),
        partner_id: plan.sd_plan.partner_id,
        pda_id: plan.sd_plan.pda_id,
        pda_version: "1",
        schema_digest: plan.sd_plan.schema_digest,
        ingestion_mode: "MODE_B",
      },
    });
    expect(result.bundle.status).toBe("not_configured");
  });

  it("rejects MODE_B with sd_enabled=true with exact code and no proof context", () => {
    expect(() =>
      buildSdPlan({
        pda_config: { sd_enabled: true, ingestion_mode: "MODE_B", pda_id: b32("pda"), pda_version: 1n },
        partner_id: b32("partner"),
        schema: baseSchema,
      }),
    ).toThrow(SdError);
    try {
      buildSdPlan({
        pda_config: { sd_enabled: true, ingestion_mode: "MODE_B", pda_id: b32("pda"), pda_version: 1n },
        partner_id: b32("partner"),
        schema: baseSchema,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(SdError);
      expect((err as SdError).code).toBe(SdErrorCode.CONFIG_MODE_B_INCOMPATIBLE);
      expect(JSON.stringify((err as SdError).safeRefs)).not.toContain("proof");
    }
  });
});
