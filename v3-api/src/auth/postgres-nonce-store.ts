// Postgres-backed HMAC replay-nonce store. Persists the (key_id, nonce)
// reuse-window so a multi-replica orchestrator cannot accept a replayed HMAC
// request via a different replica.
//
// Behavior matches `InMemoryNonceStore` (see ./nonce-store.ts):
//   consume()  -> true  iff (key_id, nonce) was NOT seen within its TTL;
//                  the row is inserted with `expires_at = now + ttl`.
//              -> false iff a row exists with expires_at > now (replay).
//
// Concurrency: the unique PK (key_id, nonce) + ON CONFLICT DO NOTHING gives
// atomic at-most-one-acceptance across replicas. Lazy purge of expired rows
// runs on each `consume()` to amortize the background sweeper.
//
// V3 isolation: no @cealis/shared imports, no V1 env vars. Caller injects the
// `postgres()` Sql client at composition root.

import type { Sql } from "postgres";
import { HMAC_NONCE_REUSE_WINDOW_SECONDS } from "../types/auth.js";
import type { NonceStore } from "./nonce-store.js";

export interface PostgresNonceStoreOptions {
  /** postgres-js Sql client bound to the V3 orchestrator DB. */
  readonly sql: Sql;
  /**
   * Lazy-purge: only run the DELETE-expired sweep at most once per N ms.
   * Defaults to 60s. Set to 0 to purge on every consume() (useful in tests).
   */
  readonly purgeIntervalMs?: number;
}

export class PostgresNonceStore implements NonceStore {
  private readonly sql: Sql;
  private readonly purgeIntervalMs: number;
  private lastPurgeAtMs = 0;

  constructor(options: PostgresNonceStoreOptions) {
    this.sql = options.sql;
    this.purgeIntervalMs = options.purgeIntervalMs ?? 60_000;
  }

  async consume(input: {
    keyId: string;
    nonce: string;
    nowMs?: number;
    ttlSeconds?: number;
  }): Promise<boolean> {
    const nowMs = input.nowMs ?? Date.now();
    const ttlSeconds = input.ttlSeconds ?? HMAC_NONCE_REUSE_WINDOW_SECONDS;
    await this.maybePurge(nowMs);

    const now = new Date(nowMs);
    const expiresAt = new Date(nowMs + ttlSeconds * 1000);

    // Atomic "insert if absent OR existing row already expired".
    // ON CONFLICT (key_id, nonce) DO UPDATE only when the prior row has
    // expired — that path counts as a fresh acceptance.
    const rows = await this.sql<{ inserted: boolean }[]>`
      INSERT INTO nonces (key_id, nonce, expires_at, created_at)
      VALUES (${input.keyId}, ${input.nonce}, ${expiresAt}, ${now})
      ON CONFLICT (key_id, nonce) DO UPDATE
        SET expires_at = EXCLUDED.expires_at,
            created_at = EXCLUDED.created_at
        WHERE nonces.expires_at <= ${now}
      RETURNING (xmax = 0) AS inserted
    `;

    // Row returned with inserted=true  → fresh acceptance (pure INSERT)
    // Row returned with inserted=false → revived an expired row → fresh acceptance
    // No row returned                  → conflict, prior row still live → replay
    return rows.length > 0;
  }

  /** Run the expired-row sweep at most every `purgeIntervalMs`. */
  private async maybePurge(nowMs: number): Promise<void> {
    if (this.purgeIntervalMs > 0 && nowMs - this.lastPurgeAtMs < this.purgeIntervalMs) {
      return;
    }
    this.lastPurgeAtMs = nowMs;
    const now = new Date(nowMs);
    await this.sql`DELETE FROM nonces WHERE expires_at <= ${now}`;
  }

  /** For tests: forced purge regardless of interval. */
  async purgeExpired(nowMs?: number): Promise<number> {
    const now = new Date(nowMs ?? Date.now());
    const rows = await this.sql<{ count: number }[]>`
      WITH d AS (DELETE FROM nonces WHERE expires_at <= ${now} RETURNING 1)
      SELECT COUNT(*)::int AS count FROM d
    `;
    return rows[0]?.count ?? 0;
  }

  /** For tests: count rows currently tracked. */
  async size(): Promise<number> {
    const rows = await this.sql<{ count: number }[]>`SELECT COUNT(*)::int AS count FROM nonces`;
    return rows[0]?.count ?? 0;
  }
}
