import { describe, it, expect } from "vitest";
import {
  buildCanonicalRequest,
  buildWebhookSignaturePreimage,
} from "../../src/auth/canonical-request.js";
import {
  HMAC_REPLAY_WINDOW_SECONDS,
  HMAC_NONCE_REUSE_WINDOW_SECONDS,
  SUBJECT_SESSION_TTL_SECONDS,
} from "../../src/types/auth.js";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

describe("Partner HMAC canonical-request (S2-5 §1.2 verbatim)", () => {
  it("produces preimage = METHOD\\n PATH\\n TIMESTAMP\\n NONCE\\n sha256(body)", () => {
    const body = new TextEncoder().encode('{"hello":"world"}');
    const preimage = buildCanonicalRequest({
      method: "POST",
      pathWithQuery: "/v1/ingestions",
      timestamp: "1716800000",
      nonce: "AAAA",
      rawRequestBody: body,
    });
    const text = new TextDecoder().decode(preimage);
    const expectedBodyHex = bytesToHex(sha256(body));
    expect(text).toBe(`POST\n/v1/ingestions\n1716800000\nAAAA\n${expectedBodyHex}`);
  });

  it("uses LF (0x0A) not CRLF", () => {
    const preimage = buildCanonicalRequest({
      method: "GET",
      pathWithQuery: "/v1/health",
      timestamp: "1",
      nonce: "n",
      rawRequestBody: new Uint8Array(0),
    });
    expect(preimage.indexOf(0x0d)).toBe(-1); // no CR
    const lfCount = preimage.filter((b) => b === 0x0a).length;
    expect(lfCount).toBe(4); // four \n separators
  });
});

describe("Webhook signature preimage (S2-5 §7.2 verbatim)", () => {
  it("produces preimage = utf8(timestamp) '.' rawBody (single dot byte)", () => {
    const body = new TextEncoder().encode('{"event":"reveal.finalized"}');
    const preimage = buildWebhookSignaturePreimage("1716800000", body);
    // Decode prefix to "1716800000."
    const prefixText = new TextDecoder().decode(preimage.slice(0, 11));
    expect(prefixText).toBe("1716800000.");
    // Tail bytes match the body verbatim.
    const tailBytes = preimage.slice(11);
    expect(Array.from(tailBytes)).toEqual(Array.from(body));
  });

  it("dot is exactly one ASCII byte (0x2E)", () => {
    const preimage = buildWebhookSignaturePreimage("0", new Uint8Array(0));
    expect(preimage.length).toBe(2);
    expect(preimage[0]).toBe(0x30); // '0'
    expect(preimage[1]).toBe(0x2e); // '.'
  });
});

describe("Auth replay-window constants", () => {
  it("300s replay window for HMAC and webhook (§1.2 + §7.2)", () => {
    expect(HMAC_REPLAY_WINDOW_SECONDS).toBe(300);
  });

  it("24h nonce reuse window (§1.2 line 175)", () => {
    expect(HMAC_NONCE_REUSE_WINDOW_SECONDS).toBe(86400);
  });

  it("subject session 7-day TTL (§6.1)", () => {
    expect(SUBJECT_SESSION_TTL_SECONDS).toBe(7 * 24 * 60 * 60);
  });
});
