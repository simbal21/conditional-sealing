import { HttpProblem, problemFromCode } from "../errors/index.js";
import type { PreSigmaPayload } from "./payload-build.js";
import type { PreSigmaSessionBinder, PreSigmaSessionRecord } from "./session-bind.js";

export interface PreSigmaConfirmationRequest {
  readonly payload_digest: string;
  readonly completed_confirmations: readonly string[];
  readonly subject_user_id?: string;
}

export class InMemoryPreSigmaConfirmationStore {
  constructor(private readonly binder: PreSigmaSessionBinder) {}

  submit(input: {
    readonly onboarding_link_id: string;
    readonly partner_id: string;
    readonly pda_id: string;
    readonly payload: PreSigmaPayload;
    readonly request: PreSigmaConfirmationRequest;
    readonly now?: Date;
    readonly correlationId?: string;
  }): PreSigmaSessionRecord {
    const expected = new Set(input.payload.confirmation_checklist);
    for (const item of input.request.completed_confirmations) expected.delete(item);
    if (input.request.payload_digest !== input.payload.payload_digest || expected.size > 0) {
      throw new HttpProblem(
        problemFromCode("REQUEST_MALFORMED", input.correlationId ?? "pre_sigma", {
          detail: "Pre-sigma confirmations are incomplete or bound to a different payload digest.",
        }),
      );
    }
    return this.binder.issue({
      onboarding_link_id: input.onboarding_link_id,
      partner_id: input.partner_id,
      pda_id: input.pda_id,
      pre_sigma_payload_digest: input.payload.payload_digest,
      subject_user_id: input.request.subject_user_id,
      now: input.now,
    });
  }
}
