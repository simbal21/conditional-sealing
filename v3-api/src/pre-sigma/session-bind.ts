import { randomUUID } from "node:crypto";
import { HttpProblem, problemFromCode } from "../errors/index.js";

export interface PreSigmaSessionRecord {
  readonly session_id: string;
  readonly onboarding_link_id: string;
  readonly partner_id: string;
  readonly pda_id: string;
  readonly subject_user_id?: string;
  readonly pre_sigma_payload_digest: string;
  readonly confirmations_completed_at: string;
  readonly created_at: string;
  readonly expires_at: string;
  readonly consumed_at?: string | null;
}

export class PreSigmaSessionBinder {
  private readonly records = new Map<string, PreSigmaSessionRecord>();

  issue(input: {
    readonly onboarding_link_id: string;
    readonly partner_id: string;
    readonly pda_id: string;
    readonly pre_sigma_payload_digest: string;
    readonly subject_user_id?: string;
    readonly now?: Date;
    readonly ttlMs?: number;
  }): PreSigmaSessionRecord {
    const now = input.now ?? new Date();
    const record: PreSigmaSessionRecord = {
      session_id: randomUUID(),
      onboarding_link_id: input.onboarding_link_id,
      partner_id: input.partner_id,
      pda_id: input.pda_id,
      subject_user_id: input.subject_user_id,
      pre_sigma_payload_digest: input.pre_sigma_payload_digest,
      confirmations_completed_at: now.toISOString(),
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + (input.ttlMs ?? 24 * 60 * 60 * 1000)).toISOString(),
      consumed_at: null,
    };
    this.records.set(record.session_id, record);
    return record;
  }

  consumeOnce(sessionId: string, now = new Date(), correlationId = "pre_sigma"): PreSigmaSessionRecord {
    const record = this.records.get(sessionId);
    if (!record || record.consumed_at || new Date(record.expires_at).getTime() <= now.getTime()) {
      throw new HttpProblem(
        problemFromCode("IDEMPOTENCY_KEY_CONFLICT", correlationId, {
          detail: "pre_sigma_session_id is unknown, expired, or already consumed.",
        }),
      );
    }
    const consumed = { ...record, consumed_at: now.toISOString() };
    this.records.set(sessionId, consumed);
    return consumed;
  }

  get(sessionId: string): PreSigmaSessionRecord | undefined {
    return this.records.get(sessionId);
  }
}
