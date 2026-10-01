// verifyRefusalArtifact — unit tests covering all 10 G4 refusal reason codes
// (0x01..0x0A) per S2-5 §10.4 + S2-2 §14.
//
// Closes an internal integration-gap item verification (2026-05-14).

import { describe, expect, it } from "vitest";
import { verifyRefusalArtifact } from "../src/verify-refusal-artifact.js";
import { webhookSignatureHex } from "../src/verify-webhook.js";
import type {
  Hex32,
  RefusalEntryShape,
  WebhookHeaders,
} from "../src/types.js";

const textEncoder = new TextEncoder();
const SECRET = textEncoder.encode("test_refusal_webhook_secret");

const REASON_LABEL: Record<number, string> = {
  0x01: "legal_compel",
  0x02: "art_17_erasure",
  0x03: "art_18_restriction",
  0x04: "integrity_fail",
  0x05: "chain_mismatch",
  0x06: "plugin_deprecated",
  0x07: "authority_deprecated",
  0x08: "dsl_deprecated",
  0x09: "oracle_deprecated",
  0x0a: "opt_out_active",
};

const ENCRYPTED_CODES: ReadonlySet<number> = new Set([0x02, 0x03]);
const ADVISORY_CODE = 0x0a;

const ZERO_HEX32 =
  "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex32;

function formatHex(code: number): string {
  return `0x${code.toString(16).padStart(2, "0")}`;
}

function makeRefusalEntry(
  code: number,
  overrides: Partial<RefusalEntryShape> = {},
): RefusalEntryShape {
  const isEncrypted = ENCRYPTED_CODES.has(code);
  const blocking = code >= 0x01 && code <= 0x09;
  return {
    refusal_id: `refusal-${formatHex(code)}`,
    authorization_id: ZERO_HEX32,
    h_commit: ZERO_HEX32,
    partner_id: "demo-partner",
    pda_id: "demo-pda",
    reason_code: code,
    reason_code_hex: formatHex(code),
    reason_label: REASON_LABEL[code] ?? "unknown",
    reason_visibility: isEncrypted ? "encrypted" : "plaintext",
    ...(isEncrypted ? { encrypted_reason_ref: `vault://refusal/${formatHex(code)}` } : {}),
    refused_at: "2026-05-11T00:00:00.000Z",
    blocking,
    ...overrides,
  };
}

function makeWebhookEnvelope(entry: RefusalEntryShape): Uint8Array {
  return textEncoder.encode(
    JSON.stringify({
      event_id: entry.refusal_id,
      schema_version: "s2-5.1",
      event_type: "g4.refused",
      created_at: entry.refused_at,
      partner_id: entry.partner_id,
      pda_id: entry.pda_id,
      data: {
        authorizationId: entry.authorization_id,
        h_commit: entry.h_commit,
        reason_code: entry.reason_code_hex,
        reason_label: entry.reason_label,
        reason_visibility: entry.reason_visibility,
        blocking: entry.blocking,
        ...(entry.encrypted_reason_ref === undefined
          ? {}
          : { encrypted_reason_ref: entry.encrypted_reason_ref }),
      },
    }),
  );
}

function signedHeaders(
  rawBody: Uint8Array,
  secret: Uint8Array,
  timestamp: string,
  entry: RefusalEntryShape,
  overrides: Partial<WebhookHeaders> = {},
): WebhookHeaders {
  const sig = webhookSignatureHex(timestamp, rawBody, secret);
  return {
    "x-cealis-signature": `sha256=${sig}`,
    "x-cealis-timestamp": timestamp,
    "x-cealis-event": "g4.refused",
    "x-cealis-delivery": entry.refusal_id,
    ...overrides,
  };
}

describe("verifyRefusalArtifact — all 10 G4 refusal codes pass when fully consistent", () => {
  const NOW = new Date("2026-05-11T00:00:00.000Z");
  const TS = String(Math.floor(NOW.getTime() / 1000));

  const allCodes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];

  for (const code of allCodes) {
    it(`verifies code ${formatHex(code)} (${REASON_LABEL[code]}) end-to-end`, async () => {
      const entry = makeRefusalEntry(code);
      const body = makeWebhookEnvelope(entry);
      const headers = signedHeaders(body, SECRET, TS, entry);
      const result = await verifyRefusalArtifact({
        webhookHeaders: headers,
        webhookBody: body,
        webhookSecret: SECRET,
        refusalEntry: entry,
        now: NOW,
      });
      expect(result.verified).toBe(true);
      expect(result.kind).toBe("refusal");
      expect(result.reasonCode).toBe(code);
      expect(result.reasonLabel).toBe(REASON_LABEL[code]);
      expect(result.blocking).toBe(code !== ADVISORY_CODE);
      expect(result.checks.webhook.overall).toBe("pass");
      expect(result.checks.eventType.status).toBe("pass");
      expect(result.checks.reasonCode.status).toBe("pass");
      expect(result.checks.encryptedReason.status).toBe("pass");
      expect(result.checks.visibilityConsistency.status).toBe("pass");
      expect(result.checks.blockingConsistency.status).toBe("pass");
      expect(result.checks.reasonCodeHex.status).toBe("pass");
      if (ENCRYPTED_CODES.has(code)) {
        expect(result.reasonVisibility).toBe("encrypted");
        expect(result.encryptedReasonRef).toBeDefined();
      } else {
        expect(result.reasonVisibility).toBe("plaintext");
        expect(result.encryptedReasonRef).toBeUndefined();
      }
    });
  }
});

describe("verifyRefusalArtifact — content validation failures", () => {
  const NOW = new Date("2026-05-11T00:00:00.000Z");
  const TS = String(Math.floor(NOW.getTime() / 1000));

  it("fails when reason_code is out of range", async () => {
    const entry = makeRefusalEntry(0x04);
    // Force an invalid code without re-deriving everything.
    const bogus = { ...entry, reason_code: 0xff, reason_code_hex: "0xff" };
    const body = makeWebhookEnvelope(bogus);
    const headers = signedHeaders(body, SECRET, TS, bogus);
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: bogus,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.reasonCode.status).toBe("fail");
    expect(result.checks.reasonCode.code).toBe("REFUSAL.REASON_CODE.OUT_OF_RANGE");
  });

  it("fails when encrypted_reason_ref is missing for 0x02", async () => {
    const entry = makeRefusalEntry(0x02);
    const broken: RefusalEntryShape = {
      refusal_id: entry.refusal_id,
      authorization_id: entry.authorization_id,
      h_commit: entry.h_commit,
      partner_id: entry.partner_id,
      pda_id: entry.pda_id,
      reason_code: entry.reason_code,
      reason_code_hex: entry.reason_code_hex,
      reason_label: entry.reason_label,
      reason_visibility: entry.reason_visibility,
      refused_at: entry.refused_at,
      blocking: entry.blocking,
      // encrypted_reason_ref omitted on purpose
    };
    const body = makeWebhookEnvelope(broken);
    const headers = signedHeaders(body, SECRET, TS, broken);
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: broken,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.encryptedReason.status).toBe("fail");
    expect(result.checks.encryptedReason.code).toBe("REFUSAL.ENCRYPTED_REASON.MISSING");
  });

  it("fails when encrypted_reason_ref is set for a plaintext code (0x04)", async () => {
    const entry = makeRefusalEntry(0x04, {
      encrypted_reason_ref: "vault://should-not-be-here",
    });
    const body = makeWebhookEnvelope(entry);
    const headers = signedHeaders(body, SECRET, TS, entry);
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: entry,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.encryptedReason.status).toBe("fail");
    expect(result.checks.encryptedReason.code).toBe("REFUSAL.ENCRYPTED_REASON.UNEXPECTED");
  });

  it("fails when reason_visibility does not match the code's encrypted class", async () => {
    const entry = makeRefusalEntry(0x02, { reason_visibility: "plaintext" });
    const body = makeWebhookEnvelope(entry);
    const headers = signedHeaders(body, SECRET, TS, entry);
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: entry,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.visibilityConsistency.status).toBe("fail");
    expect(result.checks.visibilityConsistency.code).toBe("REFUSAL.VISIBILITY.MISMATCH");
  });

  it("fails when blocking flag is wrong for 0x0A advisory code", async () => {
    const entry = makeRefusalEntry(0x0a, { blocking: true });
    const body = makeWebhookEnvelope(entry);
    const headers = signedHeaders(body, SECRET, TS, entry);
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: entry,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.blockingConsistency.status).toBe("fail");
    expect(result.checks.blockingConsistency.code).toBe("REFUSAL.BLOCKING.MISMATCH");
  });

  it("fails when reason_code_hex does not match numeric code", async () => {
    const entry = makeRefusalEntry(0x05, { reason_code_hex: "0xff" });
    const body = makeWebhookEnvelope(entry);
    const headers = signedHeaders(body, SECRET, TS, entry);
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: entry,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.reasonCodeHex.status).toBe("fail");
    expect(result.checks.reasonCodeHex.code).toBe("REFUSAL.REASON_CODE_HEX.MISMATCH");
  });

  it("fails when event_type header is wrong", async () => {
    const entry = makeRefusalEntry(0x01);
    const body = makeWebhookEnvelope(entry);
    const headers = signedHeaders(body, SECRET, TS, entry, {
      "x-cealis-event": "reveal.finalized",
    });
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: entry,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.eventType.status).toBe("fail");
    expect(result.checks.eventType.code).toBe("REFUSAL.EVENT_TYPE.MISMATCH");
  });
});

describe("verifyRefusalArtifact — webhook precondition gates", () => {
  const NOW = new Date("2026-05-11T00:00:00.000Z");
  const TS = String(Math.floor(NOW.getTime() / 1000));

  it("skips content checks when webhook signature fails", async () => {
    const entry = makeRefusalEntry(0x01);
    const body = makeWebhookEnvelope(entry);
    const headers: WebhookHeaders = {
      "x-cealis-signature": "sha256=00",
      "x-cealis-timestamp": TS,
      "x-cealis-event": "g4.refused",
      "x-cealis-delivery": entry.refusal_id,
    };
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: entry,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.webhook.checks.signature.status).toBe("fail");
    expect(result.checks.eventType.status).toBe("skipped");
    expect(result.checks.reasonCode.status).toBe("skipped");
    expect(result.checks.encryptedReason.status).toBe("skipped");
    expect(result.checks.visibilityConsistency.status).toBe("skipped");
    expect(result.checks.blockingConsistency.status).toBe("skipped");
    expect(result.checks.reasonCodeHex.status).toBe("skipped");
  });

  it("skips content checks when replay window is exceeded", async () => {
    const entry = makeRefusalEntry(0x04);
    const body = makeWebhookEnvelope(entry);
    const staleTs = String(Math.floor(NOW.getTime() / 1000) - 1000);
    const headers = signedHeaders(body, SECRET, staleTs, entry);
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: entry,
      now: NOW,
    });
    expect(result.verified).toBe(false);
    expect(result.checks.webhook.checks.replayWindow.code).toBe("WEBHOOK_REPLAY.OUTSIDE_WINDOW");
    expect(result.checks.eventType.status).toBe("skipped");
  });

  it("respects default-now when caller does not provide one", async () => {
    // We can't deterministically test current time, but we CAN verify the
    // path: pass a fresh timestamp and let default Date() carry through.
    const entry = makeRefusalEntry(0x04);
    const liveTs = String(Math.floor(Date.now() / 1000));
    const body = makeWebhookEnvelope(entry);
    const headers = signedHeaders(body, SECRET, liveTs, entry);
    const result = await verifyRefusalArtifact({
      webhookHeaders: headers,
      webhookBody: body,
      webhookSecret: SECRET,
      refusalEntry: entry,
      // no `now` — should default to new Date()
    });
    expect(result.verified).toBe(true);
  });
});
