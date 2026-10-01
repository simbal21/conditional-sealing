import { describe, expect, it } from "vitest";
import { HttpProblem } from "../../src/errors/index.js";
import { createDefaultSubjectRouteContext } from "../../src/subject/index.js";
import { getPreSigmaPayload } from "../../src/subject/routes-pre-sigma-payload.js";
import { submitPreSigmaConfirmations } from "../../src/subject/routes-pre-sigma-confirmations.js";

describe("pre-sigma confirmations bind to ingestion", () => {
  it("returns session_id, Phase B consumes once, second consume fails with 409", () => {
    const context = createDefaultSubjectRouteContext();
    const payload = getPreSigmaPayload(context, "token_demo");
    const result = submitPreSigmaConfirmations(context, "token_demo", {
      payload_digest: payload.payload_digest,
      completed_confirmations: payload.confirmation_checklist,
      subject_user_id: "subject_demo",
    });
    expect(result.pre_sigma_session_id).toMatch(/[0-9a-f-]+/);
    const consumed = context.preSigmaBinder.consumeOnce(result.pre_sigma_session_id);
    expect(consumed.pda_id).toBe("pda_demo");
    expect(() => context.preSigmaBinder.consumeOnce(result.pre_sigma_session_id)).toThrow(HttpProblem);
    try {
      context.preSigmaBinder.consumeOnce(result.pre_sigma_session_id);
    } catch (error) {
      expect(error).toBeInstanceOf(HttpProblem);
      expect((error as HttpProblem).body.status).toBe(409);
      expect((error as HttpProblem).body.code).toBe("IDEMPOTENCY.KEY_CONFLICT");
    }
  });
});
