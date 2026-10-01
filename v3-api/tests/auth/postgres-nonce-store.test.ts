// Postgres nonce-store tests. Opt-in via V3_TEST_PG_URL; SKIPs when unset.
//
// D5 adversarial probe: a replay of the same (key_id, nonce) within the TTL
// MUST be rejected — the UNIQUE PK + ON CONFLICT semantics enforce it at the
// DB level, not just in app code.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresNonceStore } from "../../src/auth/postgres-nonce-store.js";
import { createPgTestContext, TEST_PG_URL } from "../_helpers/pg-test-helper.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

describeIfPg("PostgresNonceStore (V3_TEST_PG_URL)", () => {
  let ctx: Awaited<ReturnType<typeof createPgTestContext>>;
  let store: PostgresNonceStore;
  let P: string; // per-suite key/nonce prefix to avoid cross-file collisions

  beforeAll(async () => {
    ctx = await createPgTestContext();
    if (!ctx) return;
    store = new PostgresNonceStore({ sql: ctx.sql, purgeIntervalMs: 0 });
    P = `${ctx.prefix}nonce-`;
  });

  afterAll(async () => {
    if (ctx) await ctx.end();
  });

  // Suite-scoped row count.
  async function scopedSize(): Promise<number> {
    const rows = await ctx!.sql<{ count: number }[]>`
      SELECT COUNT(*)::int AS count FROM nonces
      WHERE key_id LIKE ${ctx!.prefix + "%"} OR nonce LIKE ${ctx!.prefix + "%"}
    `;
    return rows[0]?.count ?? 0;
  }

  it("accepts a fresh nonce", async () => {
    const before = await scopedSize();
    const ok = await store.consume({
      keyId: `${P}k1`,
      nonce: `${P}n-fresh`,
      nowMs: 1_000_000,
      ttlSeconds: 60,
    });
    expect(ok).toBe(true);
    expect((await scopedSize()) - before).toBe(1);
  });

  it("rejects a replayed nonce within the TTL window", async () => {
    const first = await store.consume({
      keyId: `${P}k1`,
      nonce: `${P}n-replay`,
      nowMs: 1_000_000,
      ttlSeconds: 60,
    });
    const second = await store.consume({
      keyId: `${P}k1`,
      nonce: `${P}n-replay`,
      nowMs: 1_001_000,
      ttlSeconds: 60,
    });
    expect(first).toBe(true);
    expect(second).toBe(false);
  });

  it("accepts the same nonce after TTL expiry", async () => {
    const first = await store.consume({
      keyId: `${P}k1`,
      nonce: `${P}n-revival`,
      nowMs: 1_000_000,
      ttlSeconds: 60,
    });
    const second = await store.consume({
      keyId: `${P}k1`,
      nonce: `${P}n-revival`,
      nowMs: 1_000_000 + 61_000,
      ttlSeconds: 60,
    });
    expect(first).toBe(true);
    expect(second).toBe(true);
  });

  it("isolates nonces by key_id", async () => {
    const a = await store.consume({
      keyId: `${P}kA`,
      nonce: `${P}shared`,
      nowMs: 1_000_000,
      ttlSeconds: 60,
    });
    const b = await store.consume({
      keyId: `${P}kB`,
      nonce: `${P}shared`,
      nowMs: 1_000_000,
      ttlSeconds: 60,
    });
    expect(a).toBe(true);
    expect(b).toBe(true);
  });

  it("purges expired rows", async () => {
    // Use a dedicated key_id so we count rows owned strictly by this test.
    const KEY = `${P}purge`;
    await store.consume({
      keyId: KEY,
      nonce: `${P}n-old`,
      nowMs: 1_000_000,
      ttlSeconds: 60,
    });
    await store.consume({
      keyId: KEY,
      nonce: `${P}n-new`,
      nowMs: 1_000_000 + 30_000,
      ttlSeconds: 60,
    });
    // Forced purge at t=1,000,070 — first row expired (60s TTL passed), second
    // not yet (TTL ends at +90s). Suite-scoped delete to avoid clobbering
    // peers running in parallel.
    const cutoff = new Date(1_000_000 + 70_000);
    const result = await ctx!.sql<{ deleted: number }[]>`
      WITH d AS (
        DELETE FROM nonces
        WHERE expires_at <= ${cutoff}
          AND (key_id = ${KEY})
        RETURNING 1
      )
      SELECT COUNT(*)::int AS deleted FROM d
    `;
    expect(result[0]?.deleted).toBe(1);
  });
});
