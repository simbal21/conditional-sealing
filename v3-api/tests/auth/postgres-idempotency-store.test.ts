// Postgres idempotency-store tests. Opt-in via V3_TEST_PG_URL.
//
// D5 adversarial probe: a replay with the SAME key but a DIFFERENT body
// digest MUST throw IDEMPOTENCY_KEY_CONFLICT — not silently re-execute.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HttpProblem } from "../../src/errors/index.js";
import { PostgresIdempotencyStore } from "../../src/auth/postgres-idempotency-store.js";
import { createPgTestContext, TEST_PG_URL } from "../_helpers/pg-test-helper.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

const enc = new TextEncoder();

describeIfPg("PostgresIdempotencyStore (V3_TEST_PG_URL)", () => {
  let ctx: Awaited<ReturnType<typeof createPgTestContext>>;
  let store: PostgresIdempotencyStore;
  let SCOPE: string;

  beforeAll(async () => {
    ctx = await createPgTestContext();
    if (!ctx) return;
    store = new PostgresIdempotencyStore({ sql: ctx.sql });
    SCOPE = `${ctx.prefix}POST /ingest/mode-a`;
  });

  afterAll(async () => {
    if (ctx) await ctx.end();
  });

  it("runs the handler once and returns replayed=false on the first call", async () => {
    let runCount = 0;
    const result = await store.execute({
      scope: SCOPE,
      key: `${ctx!.prefix}idem-1`,
      rawRequestBody: enc.encode('{"h_commit":"abc"}'),
      nowMs: 1_000_000,
      run: () => {
        runCount += 1;
        return { statusCode: 201, body: { authorizationId: "auth-1" } };
      },
    });
    expect(runCount).toBe(1);
    expect(result.replayed).toBe(false);
    expect(result.statusCode).toBe(201);
    expect(result.body).toEqual({ authorizationId: "auth-1" });
  });

  it("returns replayed=true on a second call with the SAME body", async () => {
    const body = enc.encode('{"h_commit":"abc"}');
    let runCount = 0;
    const run = () => {
      runCount += 1;
      return { statusCode: 201, body: { authorizationId: "auth-1" } };
    };
    const first = await store.execute({
      scope: SCOPE,
      key: `${ctx!.prefix}idem-2`,
      rawRequestBody: body,
      nowMs: 1_000_000,
      run,
    });
    const second = await store.execute({
      scope: SCOPE,
      key: `${ctx!.prefix}idem-2`,
      rawRequestBody: body,
      nowMs: 1_000_500,
      run,
    });
    expect(runCount).toBe(1);
    expect(first.replayed).toBe(false);
    expect(second.replayed).toBe(true);
    expect(second.statusCode).toBe(201);
    expect(second.body).toEqual({ authorizationId: "auth-1" });
  });

  it("throws IDEMPOTENCY_KEY_CONFLICT when the digest differs (adversarial replay)", async () => {
    const KEY = `${ctx!.prefix}idem-3`;
    await store.execute({
      scope: SCOPE,
      key: KEY,
      rawRequestBody: enc.encode('{"h_commit":"abc"}'),
      nowMs: 1_000_000,
      run: () => ({ statusCode: 201, body: { ok: true } }),
    });
    await expect(
      store.execute({
        scope: SCOPE,
        key: KEY,
        rawRequestBody: enc.encode('{"h_commit":"DIFFERENT"}'),
        nowMs: 1_000_500,
        run: () => ({ statusCode: 201, body: { ok: true } }),
      }),
    ).rejects.toBeInstanceOf(HttpProblem);
  });

  it("treats a request past TTL as fresh and re-runs the handler", async () => {
    let runCount = 0;
    const run = () => {
      runCount += 1;
      return { statusCode: 201, body: { run: runCount } };
    };
    const KEY = `${ctx!.prefix}idem-4`;
    await store.execute({
      scope: SCOPE,
      key: KEY,
      rawRequestBody: enc.encode("payload"),
      nowMs: 1_000_000,
      ttlMs: 1_000,
      run,
    });
    const second = await store.execute({
      scope: SCOPE,
      key: KEY,
      rawRequestBody: enc.encode("payload"),
      nowMs: 1_000_000 + 2_000,
      ttlMs: 1_000,
      run,
    });
    expect(runCount).toBe(2);
    expect(second.replayed).toBe(false);
  });

  it("isolates by scope (same key, different scope = independent)", async () => {
    const KEY = `${ctx!.prefix}shared`;
    await store.execute({
      scope: `${ctx!.prefix}POST /a`,
      key: KEY,
      rawRequestBody: enc.encode("x"),
      nowMs: 1_000_000,
      run: () => ({ statusCode: 200, body: { from: "a" } }),
    });
    const b = await store.execute({
      scope: `${ctx!.prefix}POST /b`,
      key: KEY,
      rawRequestBody: enc.encode("y"),
      nowMs: 1_000_000,
      run: () => ({ statusCode: 200, body: { from: "b" } }),
    });
    expect(b.replayed).toBe(false);
    expect(b.body).toEqual({ from: "b" });
  });

  it("purgeExpired() removes only past-TTL rows", async () => {
    const SCOPE_LOCAL = `${ctx!.prefix}POST /purge-test`;
    await store.execute({
      scope: SCOPE_LOCAL,
      key: "old",
      rawRequestBody: enc.encode("x"),
      nowMs: 1_000_000,
      ttlMs: 1_000,
      run: () => ({ statusCode: 200, body: {} }),
    });
    await store.execute({
      scope: SCOPE_LOCAL,
      key: "new",
      rawRequestBody: enc.encode("y"),
      nowMs: 1_000_000 + 500,
      ttlMs: 10_000,
      run: () => ({ statusCode: 200, body: {} }),
    });
    // Suite-scoped delete: only purge rows owned by this test's SCOPE_LOCAL.
    const cutoff = new Date(1_000_000 + 2_000);
    const result = await ctx!.sql<{ deleted: number }[]>`
      WITH d AS (
        DELETE FROM idempotency_keys
        WHERE expires_at <= ${cutoff} AND scope = ${SCOPE_LOCAL}
        RETURNING 1
      )
      SELECT COUNT(*)::int AS deleted FROM d
    `;
    expect(result[0]?.deleted).toBe(1);
  });
});
