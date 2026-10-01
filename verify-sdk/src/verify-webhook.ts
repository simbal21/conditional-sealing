import { timingSafeEqual } from "node:crypto";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import type { VerifyCheck, VerifyStatus, WebhookHeaders, WebhookVerificationResult } from "./types.js";
import { bytesToHex, failCheck, passCheck } from "./checks/canonicalization.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const REPLAY_WINDOW_SECONDS = 300;

export async function verifyWebhook(
  rawBody: Uint8Array,
  headers: WebhookHeaders,
  secret: Uint8Array,
  now: Date = new Date(),
): Promise<WebhookVerificationResult> {
  const timestamp = headers["x-cealis-timestamp"];
  const expected = webhookSignatureHex(timestamp, rawBody, secret);
  const signature = verifySignatureHeader(headers["x-cealis-signature"], expected);
  const timestampCheck = checkTimestamp(timestamp);
  const replayWindow = checkReplayWindow(timestamp, now);

  if (signature.status !== "pass") {
    return {
      overall: "fail",
      checks: {
        timestamp: timestampCheck,
        signature,
        replayWindow,
      },
    };
  }

  const event = parseWebhookEvent(rawBody);
  const checks = {
    timestamp: timestampCheck,
    signature,
    replayWindow,
  };
  return {
    overall: overallStatus(Object.values(checks)),
    event_id: event.event_id,
    event_type: event.event_type ?? headers["x-cealis-event"],
    checks,
  };
}

export function buildWebhookSignaturePreimage(timestamp: string, rawBody: Uint8Array): Uint8Array {
  const timestampBytes = textEncoder.encode(timestamp);
  const out = new Uint8Array(timestampBytes.length + 1 + rawBody.length);
  out.set(timestampBytes, 0);
  out[timestampBytes.length] = ".".charCodeAt(0);
  out.set(rawBody, timestampBytes.length + 1);
  return out;
}

export function webhookSignatureHex(timestamp: string, rawBody: Uint8Array, secret: Uint8Array): string {
  return bytesToHex(hmac(sha256, secret, buildWebhookSignaturePreimage(timestamp, rawBody))).slice(2);
}

function verifySignatureHeader(headerValue: string, expectedHex: string): VerifyCheck {
  const match = /^sha256=([0-9a-f]+)$/i.exec(headerValue);
  if (match === null) {
    return failCheck("WEBHOOK_SIGNATURE.MALFORMED", "Webhook signature header is malformed.");
  }
  const provided = hexToBytes(match[1] ?? "");
  const expected = hexToBytes(expectedHex);
  if (provided.length !== expected.length || !timingSafeEqual(Buffer.from(provided), Buffer.from(expected))) {
    return failCheck("WEBHOOK_SIGNATURE.MISMATCH", "Webhook signature does not match raw body.");
  }
  return passCheck("WEBHOOK_SIGNATURE.PASS");
}

function checkTimestamp(timestamp: string): VerifyCheck {
  if (!/^[0-9]+$/.test(timestamp)) {
    return failCheck("WEBHOOK_TIMESTAMP.MALFORMED", "Webhook timestamp must be unix seconds.");
  }
  return passCheck("WEBHOOK_TIMESTAMP.PASS");
}

function checkReplayWindow(timestamp: string, now: Date): VerifyCheck {
  if (!/^[0-9]+$/.test(timestamp)) {
    return failCheck("WEBHOOK_REPLAY.MALFORMED_TIMESTAMP", "Replay check cannot parse timestamp.");
  }
  const timestampMs = Number(timestamp) * 1000;
  if (!Number.isSafeInteger(timestampMs)) {
    return failCheck("WEBHOOK_REPLAY.TIMESTAMP_RANGE", "Webhook timestamp is outside safe integer range.");
  }
  const deltaSeconds = Math.abs(now.getTime() - timestampMs) / 1000;
  if (deltaSeconds > REPLAY_WINDOW_SECONDS) {
    return failCheck("WEBHOOK_REPLAY.OUTSIDE_WINDOW", "Webhook timestamp is outside the 300 second replay window.");
  }
  return passCheck("WEBHOOK_REPLAY.PASS");
}

function parseWebhookEvent(rawBody: Uint8Array): { readonly event_id?: string; readonly event_type?: string } {
  try {
    const parsed = JSON.parse(textDecoder.decode(rawBody)) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    const record = parsed as Record<string, unknown>;
    return {
      event_id: typeof record.event_id === "string" ? record.event_id : undefined,
      event_type: typeof record.event_type === "string" ? record.event_type : undefined,
    };
  } catch {
    return {};
  }
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) return new Uint8Array();
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function overallStatus(checks: readonly VerifyCheck[]): VerifyStatus {
  if (checks.some((check) => check.status === "fail")) return "fail";
  if (checks.every((check) => check.status === "skipped")) return "skipped";
  return "pass";
}
