import { describe, expect, it } from "vitest";
import { signWebhookEnvelope, verifyWebhookSignature } from "../../src/webhooks/index.js";

describe("webhook signature verification", () => {
  it("signs timestamp-dot-rawBody and verifies before JSON parse", () => {
    const timestamp = "1778500800";
    const body = { event_id: "evt_1", event_type: "reveal.finalized" };
    const signed = signWebhookEnvelope({
      envelope: { event_id: "evt_1", event_type: "reveal.finalized" },
      body,
      secret: "webhook_secret",
      timestamp,
    });
    expect(verifyWebhookSignature({
      rawBody: signed.rawBody,
      headers: signed.headers,
      secret: "webhook_secret",
      now: new Date(Number(timestamp) * 1000),
    })).toBe(true);
    const reparsedBody = new TextEncoder().encode(JSON.stringify({ event_type: "reveal.finalized", event_id: "evt_1" }));
    expect(verifyWebhookSignature({
      rawBody: reparsedBody,
      headers: signed.headers,
      secret: "webhook_secret",
      now: new Date(Number(timestamp) * 1000),
    })).toBe(false);
  });
});
