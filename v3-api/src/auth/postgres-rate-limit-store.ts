// Postgres-backed fixed-window rate-limit store. Mirrors
// `InMemoryRateLimitStore.check()` (see ./rate-limit-middleware.ts).
//
// Trade-off note: a SQL round-trip per request is heavier than an in-memory
// bucket. The Postgres store is intentionally available for multi-replica
// orchestrators where buckets must be shared, but a Redis store is a better
// fit at high RPS — this Postgres path covers the LBU correctness goal
// (no per-replica drift) while staying within the existing dep set.
//
// Semantics:
//   - Single atomic upsert per check(): increment `count` if the row's
//     `reset_at` is still in the future, OR reset to count=1 with a new
//     reset_at if the prior window expired (or the row is absent).
//   - Returns { allowed, limit, remaining, resetSeconds, retryAfterSeconds }.
//     `allowed=false` when count > limit (matches InMemory semantics —
//     limit=10 lets 10 requests through, the 11th is blocked).
//
// V3 isolation: caller-injected Sql; no V1 imports. Same RateLimitResult
// shape as the InMemory store so the existing preHandler factory can wrap
// either.

import type { Sql } from "postgres";
import type { RateLimitResult, RateLimitStore } from "./rate-limit-middleware.js";

export interface PostgresRateLimitStoreOptions {
  readonly sql: Sql;
}

export class PostgresRateLimitStore implements RateLimitStore {
  private readonly sql: Sql;

  constructor(options: PostgresRateLimitStoreOptions) {
    this.sql = options.sql;
  }

  async check(input: {
    readonly key: string;
    readonly limit: number;
    readonly windowMs: number;
    readonly nowMs?: number;
  }): Promise<RateLimitResult> {
    const nowMs = input.nowMs ?? Date.now();
    const now = new Date(nowMs);
    const newResetAt = new Date(nowMs + input.windowMs);

    // Single-statement atomic upsert. The CASE/WHERE branches decide:
    //   - existing row in-window  → count = count + 1, keep reset_at
    //   - existing row expired    → count = 1, reset_at = newResetAt
    //   - no row                  → INSERT count = 1, reset_at = newResetAt
    const rows = await this.sql<{ count: number; reset_at: Date }[]>`
      INSERT INTO rate_limit_buckets (bucket_key, count, reset_at, updated_at)
      VALUES (${input.key}, 1, ${newResetAt}, ${now})
      ON CONFLICT (bucket_key) DO UPDATE
        SET count = CASE
              WHEN rate_limit_buckets.reset_at > ${now} THEN rate_limit_buckets.count + 1
              ELSE 1
            END,
            reset_at = CASE
              WHEN rate_limit_buckets.reset_at > ${now} THEN rate_limit_buckets.reset_at
              ELSE ${newResetAt}
            END,
            updated_at = ${now}
      RETURNING count, reset_at
    `;

    if (rows.length === 0) {
      // Should be unreachable — upsert always returns a row. Defensive
      // path returns allowed=true with the requested limit to avoid
      // false-positive 429s on a DB-side anomaly.
      return {
        allowed: true,
        limit: input.limit,
        remaining: input.limit - 1,
        resetSeconds: Math.ceil(input.windowMs / 1000),
      };
    }

    const row = rows[0]!;
    const resetSeconds = Math.max(0, Math.ceil((row.reset_at.getTime() - nowMs) / 1000));
    const remaining = Math.max(input.limit - row.count, 0);

    if (row.count > input.limit) {
      return {
        allowed: false,
        limit: input.limit,
        remaining: 0,
        resetSeconds,
        retryAfterSeconds: resetSeconds,
      };
    }
    return { allowed: true, limit: input.limit, remaining, resetSeconds };
  }

  /** Background sweeper helper. */
  async purgeExpired(nowMs?: number): Promise<number> {
    const now = new Date(nowMs ?? Date.now());
    const rows = await this.sql<{ count: number }[]>`
      WITH d AS (DELETE FROM rate_limit_buckets WHERE reset_at <= ${now} RETURNING 1)
      SELECT COUNT(*)::int AS count FROM d
    `;
    return rows[0]?.count ?? 0;
  }

  async size(): Promise<number> {
    const rows = await this.sql<{ count: number }[]>`
      SELECT COUNT(*)::int AS count FROM rate_limit_buckets
    `;
    return rows[0]?.count ?? 0;
  }
}
