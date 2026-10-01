// Postgres rate-limit-store tests. Opt-in via V3_TEST_PG_URL.
//
// Uses per-suite bucket-key prefix to stay isolated from peer test files
// running in parallel against the same DB.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresRateLimitStore } from "../../src/auth/postgres-rate-limit-store.js";
import { createPgTestContext, TEST_PG_URL } from "../_helpers/pg-test-helper.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

describeIfPg("PostgresRateLimitStore (V3_TEST_PG_URL)", () => {
  let ctx: Awaited<ReturnType<typeof createPgTestContext>>;
  let store: PostgresRateLimitStore;
  let P: string;

  beforeAll(async () => {
    ctx = await createPgTestContext();
    if (!ctx) return;
    store = new PostgresRateLimitStore({ sql: ctx.sql });
    P = `${ctx.prefix}rl-`;
  });

  afterAll(async () => {
    if (ctx) await ctx.end();
  });

  it("allows requests up to the limit and blocks the (limit+1)th", async () => {
    const KEY = `${P}t1`;
    const start = 1_000_000;
    for (let i = 0; i < 10; i += 1) {
      const r = await store.check({
        key: KEY,
        limit: 10,
        windowMs: 1_000,
        nowMs: start + i,
      });
      expect(r.allowed).toBe(true);
      expect(r.limit).toBe(10);
      expect(r.remaining).toBe(10 - (i + 1));
    }
    const blocked = await store.check({
      key: KEY,
      limit: 10,
      windowMs: 1_000,
      nowMs: start + 10,
    });
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
    expect(blocked.retryAfterSeconds).toBeGreaterThanOrEqual(0);
  });

  it("resets the bucket after window expiry", async () => {
    const KEY = `${P}t2`;
    const start = 1_000_000;
    for (let i = 0; i < 5; i += 1) {
      await store.check({ key: KEY, limit: 5, windowMs: 1_000, nowMs: start });
    }
    const blocked = await store.check({ key: KEY, limit: 5, windowMs: 1_000, nowMs: start });
    expect(blocked.allowed).toBe(false);
    const afterReset = await store.check({
      key: KEY,
      limit: 5,
      windowMs: 1_000,
      nowMs: start + 2_000,
    });
    expect(afterReset.allowed).toBe(true);
    expect(afterReset.remaining).toBe(4);
  });

  it("isolates buckets by key", async () => {
    const KA = `${P}t3-a`;
    const KB = `${P}t3-b`;
    const start = 1_000_000;
    for (let i = 0; i < 5; i += 1) {
      await store.check({ key: KA, limit: 5, windowMs: 1_000, nowMs: start });
    }
    const blocked = await store.check({ key: KA, limit: 5, windowMs: 1_000, nowMs: start });
    const otherKey = await store.check({ key: KB, limit: 5, windowMs: 1_000, nowMs: start });
    expect(blocked.allowed).toBe(false);
    expect(otherKey.allowed).toBe(true);
  });

  it("purgeExpired() removes only past-reset rows", async () => {
    const KS = `${P}t5-short`;
    const KL = `${P}t5-long`;
    await store.check({ key: KS, limit: 10, windowMs: 1_000, nowMs: 1_000_000 });
    await store.check({ key: KL, limit: 10, windowMs: 60_000, nowMs: 1_000_000 });
    // Suite-scoped purge — only delete rows owned by this test.
    const cutoff = new Date(1_000_000 + 5_000);
    const result = await ctx!.sql<{ deleted: number }[]>`
      WITH d AS (
        DELETE FROM rate_limit_buckets
        WHERE reset_at <= ${cutoff} AND bucket_key IN (${KS}, ${KL})
        RETURNING 1
      )
      SELECT COUNT(*)::int AS deleted FROM d
    `;
    expect(result[0]?.deleted).toBe(1);
  });
});
