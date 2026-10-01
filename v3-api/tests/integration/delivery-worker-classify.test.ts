// Tests for the delivery-worker classifier + RetryableDeliveryFailure shape.
// The full Worker lifecycle (BullMQ-backed retry → DLQ) requires a live
// Redis and is exercised end-to-end in M8 Internal E2E Demo per the Stage-3
// roadmap. This test pins the pure-function classifier + error-class
// contracts the Worker depends on.

import { describe, expect, it } from "vitest";
import {
  classifyAttempt,
  RetryableDeliveryFailure,
} from "../../src/webhooks/delivery-worker.js";
import { WEBHOOK_DELIVERY_SUCCESS_WINDOW_MS } from "../../src/types/webhook-events.js";

describe("delivery-worker classifyAttempt", () => {
  it("classifies 2xx within window as delivered", () => {
    const ok = classifyAttempt(200, 1000);
    expect(ok.delivered).toBe(true);
    expect(ok.discarded).toBe(false);
  });

  it("classifies 2xx PAST the 30s success window as NOT delivered (matches existing bullmq-queue.ts:isRetryable)", () => {
    // §7.3: success requires <=30s. A slow 200 past the window is NOT a
    // success. The existing in-memory dispatcher (bullmq-queue.ts:100-102)
    // classifies isRetryable on statusCode alone — 200 is non-retryable, so
    // the existing pipeline treats a slow 200 as "discarded" (not retried,
    // not DLQ'd). We mirror that behavior here for V1-parity. If the spec
    // is ever revised to treat slow 200 as retryable, both classifiers move
    // together — that's a deliberate behavior change, not a code-level
    // discrepancy.
    const slow = classifyAttempt(200, WEBHOOK_DELIVERY_SUCCESS_WINDOW_MS + 1);
    expect(slow.delivered).toBe(false);
    expect(slow.discarded).toBe(true);
  });

  it("classifies 5xx as retryable (not delivered, not discarded)", () => {
    const fivexx = classifyAttempt(500, 100);
    expect(fivexx.delivered).toBe(false);
    expect(fivexx.discarded).toBe(false);
  });

  it("classifies 429 as retryable", () => {
    const ratelim = classifyAttempt(429, 50);
    expect(ratelim.delivered).toBe(false);
    expect(ratelim.discarded).toBe(false);
  });

  it("classifies 0 (network failure) as retryable", () => {
    const netfail = classifyAttempt(0, 30_000);
    expect(netfail.delivered).toBe(false);
    expect(netfail.discarded).toBe(false);
  });

  it("classifies 4xx (non-429) as discarded (terminal, no retry, no DLQ)", () => {
    const fourxx = classifyAttempt(404, 50);
    expect(fourxx.delivered).toBe(false);
    expect(fourxx.discarded).toBe(true);
    const badreq = classifyAttempt(400, 50);
    expect(badreq.discarded).toBe(true);
    const unauthz = classifyAttempt(401, 50);
    expect(unauthz.discarded).toBe(true);
  });

  it("RetryableDeliveryFailure carries safeRefs Rule-47 context", () => {
    const err = new RetryableDeliveryFailure("test", { statusCode: 503, elapsedMs: 100, attempt: 3 });
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("RetryableDeliveryFailure");
    expect(err.safeRefs.statusCode).toBe(503);
    expect(err.safeRefs.elapsedMs).toBe(100);
    expect(err.safeRefs.attempt).toBe(3);
  });
});
