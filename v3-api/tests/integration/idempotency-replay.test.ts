import { describe, expect, it } from "vitest";
import { HttpProblem } from "../../src/errors/index.js";
import { InMemoryIdempotencyStore } from "../../src/auth/index.js";

describe("idempotency replay", () => {
  it("replays same digest and rejects divergent digest with 409", async () => {
    const store = new InMemoryIdempotencyStore();
    const body = new TextEncoder().encode('{"a":1}');
    const first = await store.execute({
      scope: "partner_demo:onboarding",
      key: "idem_1",
      rawRequestBody: body,
      run: () => ({ statusCode: 201, body: { ok: true } }),
    });
    const replay = await store.execute({
      scope: "partner_demo:onboarding",
      key: "idem_1",
      rawRequestBody: body,
      run: () => ({ statusCode: 500, body: { ok: false } }),
    });
    expect(first.replayed).toBe(false);
    expect(replay.replayed).toBe(true);
    expect(replay.statusCode).toBe(201);
    await expect(
      store.execute({
        scope: "partner_demo:onboarding",
        key: "idem_1",
        rawRequestBody: new TextEncoder().encode('{"a":2}'),
        run: () => ({ statusCode: 201, body: { ok: true } }),
      }),
    ).rejects.toMatchObject({ body: expect.objectContaining({ status: 409, code: "IDEMPOTENCY.KEY_CONFLICT" }) });
    await expect(
      store.execute({
        scope: "partner_demo:onboarding",
        key: "idem_1",
        rawRequestBody: new TextEncoder().encode('{"a":3}'),
        run: () => ({ statusCode: 201, body: { ok: true } }),
      }),
    ).rejects.toBeInstanceOf(HttpProblem);
  });
});
