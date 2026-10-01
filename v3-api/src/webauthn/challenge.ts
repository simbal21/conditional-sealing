import { randomBytes, randomUUID } from "node:crypto";
import { bytesToHex } from "@noble/hashes/utils";

export type WebAuthnPurpose = "login" | "sigma_subject" | "shred_request";

export interface WebAuthnChallengeRecord {
  readonly challenge_id: string;
  readonly challenge: string;
  readonly purpose: WebAuthnPurpose;
  readonly user_id: string;
  readonly created_at: string;
  readonly expires_at: string;
  readonly consumed_at?: string | null;
}

export class InMemoryWebAuthnChallengeStore {
  private readonly records = new Map<string, WebAuthnChallengeRecord>();

  create(input: {
    readonly purpose: WebAuthnPurpose;
    readonly user_id?: string;
    readonly now?: Date;
    readonly ttlMs?: number;
  }): WebAuthnChallengeRecord {
    const now = input.now ?? new Date();
    const record: WebAuthnChallengeRecord = {
      challenge_id: randomUUID(),
      challenge: bytesToHex(randomBytes(32)),
      purpose: input.purpose,
      user_id: input.user_id ?? `subject_${randomUUID()}`,
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + (input.ttlMs ?? 5 * 60 * 1000)).toISOString(),
      consumed_at: null,
    };
    this.records.set(record.challenge_id, record);
    return record;
  }

  consume(challengeId: string, now = new Date()): WebAuthnChallengeRecord | undefined {
    const record = this.records.get(challengeId);
    if (!record || record.consumed_at) return undefined;
    if (new Date(record.expires_at).getTime() <= now.getTime()) return undefined;
    const consumed = { ...record, consumed_at: now.toISOString() };
    this.records.set(challengeId, consumed);
    return consumed;
  }
}
