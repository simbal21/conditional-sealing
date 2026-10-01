import { describe, expect, it } from "vitest";
import { SdBoundaryImpl } from "../../src/boundary/boundary.js";
import { executeSdAtCommit } from "../../src/sd-plan/execute.js";
import { createM5IngestionStub } from "../../src/__tests__/m5-stub.js";
import { SD_FAILURE_TABLE } from "../../src/types/failure-modes.js";
import { b32, buildCleartextPlan, commitCtx, dek, payload } from "./helpers.js";

describe("Phase E asymmetric isolation cross-stage", () => {
  it("reuses the M5 stub and covers all seven §15.2 stages", async () => {
    const seen: string[] = [];
    for (const row of SD_FAILURE_TABLE) {
      const plan = buildCleartextPlan();
      const stub = createM5IngestionStub();
      const escrow = await stub.execute({
        authorizationId: b32(`phase-e-${row.stage}`),
        pda_id: plan.sd_plan.pda_id,
        pda_version: plan.sd_plan.pda_version,
        schema_digest: plan.sd_plan.schema_digest,
        partner_id: plan.sd_plan.partner_id,
        ingestion_mode: "MODE_A",
        plaintext: payload(),
        dek: dek(),
      });
      const result = await SdBoundaryImpl.executeIfEscrowOk(
        escrow.kind === "ok" ? { kind: "ok" as const, value: escrow } : { kind: "err" as const, failure: escrow },
        async () => {
          const sd = await executeSdAtCommit({ plaintext: payload(), commit_ctx: commitCtx(plan), plan, dek: dek(), induce_failure_stage: row.stage });
          return sd.bundle.status === "failed"
            ? { kind: "sd_err" as const, stage: row.stage, code: sd.bundle.failures[0]!.error, partial: false }
            : { kind: "sd_ok" as const, value: sd.bundle };
        },
      );
      expect(result.escrow.kind).toBe("ok");
      expect(result.sd.kind).toBe("sd_err");
      seen.push(row.stage);
    }
    expect(seen).toHaveLength(7);
  });
});

