import { describe, expect, it } from "vitest";
import { verifyWebhook } from "../src/index.js";
import { webhookSignatureHex } from "../src/verify-webhook.js";

const textEncoder = new TextEncoder();

describe("verifyWebhook", () => {
  it("verifies timestamp-dot-rawBody HMAC and extracts event fields after signature passes", async () => {
    const rawBody = textEncoder.encode('{"event_id":"evt_1","event_type":"reveal.finalized"}');
    const secret = textEncoder.encode("webhook_secret");
    const timestamp = "1778500800";
    const result = await verifyWebhook(rawBody, signedHeaders(rawBody, secret, timestamp), secret, new Date(Number(timestamp) * 1000));
    expect(result.overall).toBe("pass");
    expect(result.event_id).toBe("evt_1");
    expect(result.event_type).toBe("reveal.finalized");
    expect(result.checks.signature.status).toBe("pass");
  });

  it("rejects stale timestamps using the 300 second replay window", async () => {
    const rawBody = textEncoder.encode('{"event_id":"evt_2","event_type":"vault.shredded"}');
    const secret = textEncoder.encode("webhook_secret");
    const timestamp = "1778500800";
    const result = await verifyWebhook(rawBody, signedHeaders(rawBody, secret, timestamp), secret, new Date((Number(timestamp) + 301) * 1000));
    expect(result.overall).toBe("fail");
    expect(result.checks.replayWindow.code).toBe("WEBHOOK_REPLAY.OUTSIDE_WINDOW");
  });

  it("does not parse JSON before signature verification", async () => {
    const invalidJson = textEncoder.encode('{"event_id":');
    const secret = textEncoder.encode("webhook_secret");
    const result = await verifyWebhook(
      invalidJson,
      {
        "x-cealis-signature": "sha256=00",
        "x-cealis-timestamp": "1778500800",
        "x-cealis-event": "reveal.finalized",
        "x-cealis-delivery": "evt_bad",
      },
      secret,
      new Date("2026-05-11T12:00:00.000Z"),
    );
    expect(result.overall).toBe("fail");
    expect(result.event_id).toBeUndefined();
    expect(result.checks.signature.status).toBe("fail");
  });

  it("fails malformed headers and malformed timestamp branches", async () => {
    const rawBody = textEncoder.encode('{"event_id":"evt_3"}');
    const secret = textEncoder.encode("webhook_secret");
    const malformedSignature = await verifyWebhook(
      rawBody,
      {
        "x-cealis-signature": "not-sha256",
        "x-cealis-timestamp": "1778500800",
        "x-cealis-event": "reveal.finalized",
        "x-cealis-delivery": "evt_3",
      },
      secret,
      new Date("2026-05-11T12:00:00.000Z"),
    );
    expect(malformedSignature.checks.signature.code).toBe("WEBHOOK_SIGNATURE.MALFORMED");

    const malformedTimestamp = await verifyWebhook(
      rawBody,
      {
        "x-cealis-signature": `sha256=${webhookSignatureHex("not-a-time", rawBody, secret)}`,
        "x-cealis-timestamp": "not-a-time",
        "x-cealis-event": "reveal.finalized",
        "x-cealis-delivery": "evt_3",
      },
      secret,
      new Date("2026-05-11T12:00:00.000Z"),
    );
    expect(malformedTimestamp.checks.timestamp.code).toBe("WEBHOOK_TIMESTAMP.MALFORMED");
    expect(malformedTimestamp.checks.replayWindow.code).toBe("WEBHOOK_REPLAY.MALFORMED_TIMESTAMP");
  });

  it("handles valid signatures over unparsable JSON without parser differential risk", async () => {
    const rawBody = textEncoder.encode('{"event_id":');
    const secret = textEncoder.encode("webhook_secret");
    const timestamp = "1778500800";
    const result = await verifyWebhook(rawBody, signedHeaders(rawBody, secret, timestamp), secret, new Date(Number(timestamp) * 1000));
    expect(result.overall).toBe("pass");
    expect(result.event_id).toBeUndefined();
  });
});

function signedHeaders(rawBody: Uint8Array, secret: Uint8Array, timestamp: string) {
  return {
    "x-cealis-signature": `sha256=${webhookSignatureHex(timestamp, rawBody, secret)}`,
    "x-cealis-timestamp": timestamp,
    "x-cealis-event": "reveal.finalized",
    "x-cealis-delivery": "evt_1",
  };
}
