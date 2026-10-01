// HMAC replay-nonce store interface.
//
// `consume()` returns Promise<boolean> because the Postgres impl must hit the
// DB. The in-memory impl is also async-shaped so middleware doesn't branch
// by store kind — composition root picks the impl, callers always `await`.
// Previously the contract was sync and the Postgres impl threw at runtime —
// see dw-quality-2 R2b-2 NEEDS-CHANGES (SHOULD-FIX-1, Rule-12 honesty).

import { HMAC_NONCE_REUSE_WINDOW_SECONDS } from "../types/auth.js";

export interface NonceStore {
  consume(input: {
    keyId: string;
    nonce: string;
    nowMs?: number;
    ttlSeconds?: number;
  }): Promise<boolean>;
}

export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();

  async consume(input: {
    keyId: string;
    nonce: string;
    nowMs?: number;
    ttlSeconds?: number;
  }): Promise<boolean> {
    const nowMs = input.nowMs ?? Date.now();
    const ttlMs = (input.ttlSeconds ?? HMAC_NONCE_REUSE_WINDOW_SECONDS) * 1000;
    this.purge(nowMs);
    const key = `${input.keyId}:${input.nonce}`;
    const expiresAt = this.seen.get(key);
    if (expiresAt !== undefined && expiresAt > nowMs) {
      return false;
    }
    this.seen.set(key, nowMs + ttlMs);
    return true;
  }

  size(): number {
    this.purge(Date.now());
    return this.seen.size;
  }

  private purge(nowMs: number): void {
    for (const [key, expiresAt] of this.seen.entries()) {
      if (expiresAt <= nowMs) this.seen.delete(key);
    }
  }
}
