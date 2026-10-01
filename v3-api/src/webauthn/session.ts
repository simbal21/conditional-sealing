import { randomBytes, randomUUID } from "node:crypto";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { SUBJECT_SESSION_TTL_SECONDS, type SubjectPrincipal } from "../types/auth.js";

const textEncoder = new TextEncoder();

export interface SubjectSessionRecord {
  readonly session_id: string;
  readonly user_id: string;
  readonly token_hash: string;
  readonly expires_at: string;
  readonly revoked_at?: string | null;
}

export interface SubjectSessionReader {
  getByTokenHash(tokenHash: string): SubjectSessionRecord | undefined | Promise<SubjectSessionRecord | undefined>;
}

export class InMemorySubjectSessionStore implements SubjectSessionReader {
  private readonly byHash = new Map<string, SubjectSessionRecord>();
  private readonly byId = new Map<string, SubjectSessionRecord>();

  create(input: { readonly user_id: string; readonly now?: Date }): { token: string; record: SubjectSessionRecord } {
    const now = input.now ?? new Date();
    const token = `${randomUUID()}.${bytesToHex(randomBytes(24))}`;
    const session_id = randomUUID();
    const record: SubjectSessionRecord = {
      session_id,
      user_id: input.user_id,
      token_hash: hashSubjectBearerToken(token),
      expires_at: new Date(now.getTime() + SUBJECT_SESSION_TTL_SECONDS * 1000).toISOString(),
      revoked_at: null,
    };
    this.byHash.set(record.token_hash, record);
    this.byId.set(record.session_id, record);
    return { token, record };
  }

  getByTokenHash(tokenHash: string): SubjectSessionRecord | undefined {
    return this.byHash.get(tokenHash);
  }

  revoke(sessionId: string): boolean {
    const record = this.byId.get(sessionId);
    if (!record) return false;
    const revoked: SubjectSessionRecord = { ...record, revoked_at: new Date().toISOString() };
    this.byId.set(sessionId, revoked);
    this.byHash.set(revoked.token_hash, revoked);
    return true;
  }
}

export function hashSubjectBearerToken(token: string): string {
  return bytesToHex(sha256(textEncoder.encode(token)));
}

export async function verifySubjectSessionToken(
  sessions: SubjectSessionReader,
  token: string,
  now: Date,
): Promise<SubjectPrincipal | undefined> {
  const record = await sessions.getByTokenHash(hashSubjectBearerToken(token));
  if (!record || record.revoked_at) return undefined;
  if (new Date(record.expires_at).getTime() <= now.getTime()) return undefined;
  return {
    user_id: record.user_id,
    session_id: record.session_id,
    expires_at: record.expires_at,
  };
}
