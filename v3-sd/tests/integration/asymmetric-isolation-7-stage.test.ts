import { describe, expect, it } from "vitest";
import { SdBoundaryImpl } from "../../src/boundary/boundary.js";
import { executeSdAtCommit } from "../../src/sd-plan/execute.js";
import { createM5IngestionStub } from "../../src/__tests__/m5-stub.js";
import { SD_FAILURE_TABLE, type SdFailureStage } from "../../src/types/failure-modes.js";
import { SdErrorCode } from "../../src/errors/codes.js";
import { b32, buildCleartextPlan, commitCtx, dek, payload } from "./helpers.js";

describe("§15.2 asymmetric isolation matrix", () => {
  it("keeps M5 escrow ok for every SD failure stage", async () => {
    for (const row of SD_FAILURE_TABLE) {
      const plan = buildCleartextPlan();
      const stub = createM5IngestionStub();
      const escrow = await stub.execute({
        authorizationId: b32(`auth-${row.stage}`),
        pda_id: plan.sd_plan.pda_id,
        pda_version: plan.sd_plan.pda_version,
        schema_digest: plan.sd_plan.schema_digest,
        partner_id: plan.sd_plan.partner_id,
        ingestion_mode: "MODE_A",
        plaintext: payload(),
        dek: dek(),
      });
      const escrowForBoundary =
        escrow.kind === "ok" ? { kind: "ok" as const, value: escrow } : { kind: "err" as const, failure: escrow };
      const boundary = await SdBoundaryImpl.executeIfEscrowOk(escrowForBoundary, async () => {
        const result = await executeSdAtCommit({
          plaintext: payload(),
          plan,
          dek: dek(),
          commit_ctx: commitCtx(plan),
          induce_failure_stage: row.stage as SdFailureStage,
        });
        return result.bundle.status === "failed"
          ? { kind: "sd_err", stage: row.stage, code: result.bundle.failures[0]?.error ?? SdErrorCode.ONBOARDING_PARTIAL_FAILURE, partial: false }
          : { kind: "sd_ok", value: result.bundle };
      });
      expect(boundary.escrow.kind).toBe("ok");
      expect(boundary.sd.kind).toBe("sd_err");
    }
  });
});
