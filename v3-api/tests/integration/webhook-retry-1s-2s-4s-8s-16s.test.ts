import { describe, expect, it } from "vitest";
import { WEBHOOK_RETRY_INTERVALS_MS } from "../../src/types/index.js";
import {
  InMemoryDeadLetterStore,
  InMemoryWebhookQueue,
  dispatchWebhookWithRetry,
  filterRetainedDeadLetters,
  retryDelayForAttempt,
  runWebhookRetryPlan,
  webhookMetadataCutoff,
} from "../../src/webhooks/index.js";

describe("webhook retry policy", () => {
  it("uses 1s/2s/4s/8s/16s and dead-letters after five failed attempts", async () => {
    const deadLetters = new InMemoryDeadLetterStore();
    const trace = await runWebhookRetryPlan({
      envelope: {
        event_id: "evt_retry",
        schema_version: "s2-5.1",
        event_type: "reveal.finalized",
        created_at: "2026-05-11T12:00:00.000Z",
        partner_id: "partner_demo",
        pda_id: "pda_demo",
        data: { authorizationId: "0xbb" },
      },
      deadLetters,
      send: () => ({ statusCode: 500 }),
    });
    expect(trace.attempts).toBe(5);
    expect(trace.plannedIntervalsMs).toEqual([...WEBHOOK_RETRY_INTERVALS_MS]);
    expect(trace.finalState).toBe("dead_letter");
    expect(deadLetters.list()).toHaveLength(1);
    const dispatched = await dispatchWebhookWithRetry({
      envelope: {
        event_id: "evt_dispatch",
        schema_version: "s2-5.1",
        event_type: "commit.finalized",
        created_at: "2026-05-11T12:00:00.000Z",
        partner_id: "partner_demo",
        pda_id: "pda_demo",
        data: { h_commit: "0xaa" },
      },
      target: { delivery_url: "https://partner.example/webhook", signing_secret: "webhook_secret" },
      deadLetters,
      sender: (_target, signed, attempt) => ({
        statusCode: attempt === 1 && signed.headers["x-cealis-event"] === "commit.finalized" ? 200 : 500,
      }),
    });
    expect(dispatched.finalState).toBe("delivered");
    const discarded = await runWebhookRetryPlan({
      envelope: {
        event_id: "evt_discard",
        schema_version: "s2-5.1",
        event_type: "commit.failed",
        created_at: "2026-05-11T12:00:00.000Z",
        partner_id: "partner_demo",
        pda_id: "pda_demo",
        data: { h_commit: "0xaa" },
      },
      deadLetters,
      send: () => ({ statusCode: 404 }),
    });
    expect(discarded.finalState).toBe("discarded");
    const queue = new InMemoryWebhookQueue();
    queue.enqueue({
      envelope: discarded.deadLetter?.envelope ?? {
        event_id: "evt_queue",
        schema_version: "s2-5.1",
        event_type: "commit.finalized",
        created_at: "2026-05-11T12:00:00.000Z",
        partner_id: "partner_demo",
        pda_id: "pda_demo",
        data: { h_commit: "0xaa" },
      },
      delivery_url: "https://partner.example/webhook",
      signing_secret_ref: "secret_ref",
    });
    expect(queue.list()).toHaveLength(1);
    expect(retryDelayForAttempt(99)).toBe(16000);
    expect(webhookMetadataCutoff(new Date("2026-05-11T00:00:00.000Z")).toISOString()).toBe(
      "2026-02-10T00:00:00.000Z",
    );
    expect(filterRetainedDeadLetters(deadLetters.list(), new Date())).toHaveLength(1);
  });
});
