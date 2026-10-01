// Closure test for Security-audit-2026-06-02 TS-API-F-09 (LOW):
// "log sanitizer implemented but not wired into Pino."
//
// Pre-fix: createFastifyApp defaulted to `{ logger: false }` and never installed
// `pinoLogFormatter`; there was no setErrorHandler, so problem-detail error
// bodies (a named §10.2 redaction target) were never run through `sanitize`.
//
// These tests construct the REAL app factory with its default options and prove
// both egress paths now redact §10.2 forbidden tokens.

import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import {
  createFastifyApp,
  DEFAULT_BODY_LIMIT_BYTES,
  type CealisApiAppDeps,
} from "../../src/server/index.js";
import { HttpProblem, problemFromCode } from "../../src/errors/index.js";

// Minimal stubs — the /internal route handler is never invoked in these tests,
// so the coordinator ports only need to satisfy the type at construction.
function stubDeps(extra: Partial<CealisApiAppDeps> = {}): CealisApiAppDeps {
  const noop = () => {
    throw new Error("not invoked in this test");
  };
  return {
    revealCoordinator: { persistAndDeliver: noop } as unknown as CealisApiAppDeps["revealCoordinator"],
    liveStateReader: {} as unknown as CealisApiAppDeps["liveStateReader"],
    coordinatorPorts: {} as unknown as CealisApiAppDeps["coordinatorPorts"],
    deliveryQueue: {} as unknown as CealisApiAppDeps["deliveryQueue"],
    ...extra,
  };
}

describe("F-09 PII redaction is wired into the default app", () => {
  it("exports an explicit body limit (no silent 1 MB default)", () => {
    expect(DEFAULT_BODY_LIMIT_BYTES).toBeGreaterThan(0);
  });

  it("routes log objects through the §10.2 redacting formatter at egress", async () => {
    const captured: string[] = [];
    const logStream = new Writable({
      write(chunk, _enc, cb) {
        captured.push(chunk.toString());
        cb();
      },
    });
    const app = createFastifyApp(stubDeps({ logStream }));
    await app.ready();

    // A log line carrying a forbidden token must be redacted by the formatter.
    app.log.info({ dek: "deadbeefdeadbeef", h_commit: "0xaa" }, "sensitive");
    // Pino flushes synchronously to the stream for these small writes.
    await new Promise((resolve) => setImmediate(resolve));

    const joined = captured.join("");
    expect(joined).toContain("[REDACTED]"); // dek value redacted
    expect(joined).not.toContain("deadbeefdeadbeef");
    expect(joined).toContain("0xaa"); // safe-ref preserved
    await app.close();
  });

  it("runs HttpProblem error bodies through sanitize before sending", async () => {
    const app = createFastifyApp(stubDeps({ fastifyOptions: { logger: false } }));
    // Register a throwaway route that throws a problem with a forbidden token in
    // a NON-safe field — the error handler must redact it.
    app.get("/test/leaky-error", async () => {
      throw new HttpProblem({
        ...problemFromCode("REQUEST_MALFORMED", "corr-1", { detail: "ok" }),
        // smuggle a forbidden-key field onto the body
        ...({ dek: "deadbeefdeadbeef" } as Record<string, unknown>),
      } as never);
    });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/test/leaky-error" });
    expect(response.statusCode).toBe(400);
    const raw = response.body;
    expect(raw).toContain("[REDACTED]");
    expect(raw).not.toContain("deadbeefdeadbeef");
    // RFC-7807 shape + status preserved through sanitize.
    expect(response.json<{ code: string; status: number }>().code).toBe("REQUEST.MALFORMED");
    await app.close();
  });

  it("sanitizes non-HttpProblem thrown errors too (no raw leak path)", async () => {
    const app = createFastifyApp(stubDeps({ fastifyOptions: { logger: false } }));
    app.get("/test/raw-throw", async () => {
      throw new Error("boom file_key=topsecretmaterial");
    });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/test/raw-throw" });
    expect(response.statusCode).toBe(500);
    expect(response.body).not.toContain("topsecretmaterial");
    expect(response.body).toContain("[REDACTED]");
    await app.close();
  });
});
