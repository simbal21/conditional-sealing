import { describe, expect, it } from "vitest";
import Fastify from "fastify";
import { HttpProblem } from "../../src/errors/index.js";
import { InMemoryRateLimitStore, createRateLimitPreHandler } from "../../src/auth/index.js";

describe("rate-limit response headers", () => {
  it("returns 429 with Retry-After and X-RateLimit headers", async () => {
    const app = Fastify();
    app.setErrorHandler((error, _request, reply) => {
      if (error instanceof HttpProblem) {
        void reply.code(error.body.status).send(error.body);
        return;
      }
      void reply.send(error);
    });
    const store = new InMemoryRateLimitStore();
    app.get(
      "/limited",
      {
        preHandler: [
          createRateLimitPreHandler({
            store,
            limit: 1,
            windowMs: 10_000,
            keyFromRequest: () => "partner_demo",
            nowMs: () => 1_000,
          }),
        ],
      },
      async () => ({ ok: true }),
    );
    expect((await app.inject({ method: "GET", url: "/limited" })).statusCode).toBe(200);
    const limited = await app.inject({ method: "GET", url: "/limited" });
    expect(limited.statusCode).toBe(429);
    expect(limited.headers["retry-after"]).toBe("10");
    expect(limited.headers["x-ratelimit-limit"]).toBe("1");
    expect(limited.headers["x-ratelimit-remaining"]).toBe("0");
    expect(limited.headers["x-ratelimit-reset"]).toBe("10");
  });
});
