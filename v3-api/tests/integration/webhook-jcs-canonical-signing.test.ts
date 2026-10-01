// JCS-canonical webhook signing — adversarial probes per
// the internal JCS design lock (not included in this export)
//
// Pins the structural property that signer.ts:20 uses
// `canonicalizeJcs(input.body)` (RFC 8785) instead of `JSON.stringify`. The
// 5 probes cover the bug class dw-quality-2 traced through the σ-as-
// authorization architecture: same logical content → same signature, no
// matter what runtime / SDK / refactor reorders the keys.

import { describe, expect, it } from "vitest";
import {
  signWebhookEnvelope,
  verifyWebhookSignature,
  WebhookEnvelopeNotJcsCompatibleError,
} from "../../src/webhooks/index.js";

const TIMESTAMP = "1778500800";
const SECRET = "webhook_secret";
const NOW = new Date(Number(TIMESTAMP) * 1000);

// ============================================================================
// Probe-1 — Top-level key-order drift defended (JCS makes byte-stability
//           structural rather than incidental on V8's insertion-order quirk).
// ============================================================================
describe("Probe-1: top-level key-order drift defended", () => {
  it("two envelopes with identical content but different key order produce identical canonical bytes + identical signatures", () => {
    const envA = {
      event_id: "evt_1",
      schema_version: "s2-5.1",
      event_type: "reveal.finalized",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: { h_commit: "0xaa" },
    };
    // Same logical content, different insertion order (last → first).
    const envB = {
      data: { h_commit: "0xaa" },
      pda_id: "pda_demo",
      partner_id: "partner_demo",
      created_at: "2026-05-21T10:00:00.000Z",
      event_type: "reveal.finalized",
      schema_version: "s2-5.1",
      event_id: "evt_1",
    };
    const signedA = signWebhookEnvelope({
      envelope: { event_id: envA.event_id, event_type: envA.event_type },
      body: envA,
      secret: SECRET,
      timestamp: TIMESTAMP,
    });
    const signedB = signWebhookEnvelope({
      envelope: { event_id: envB.event_id, event_type: envB.event_type },
      body: envB,
      secret: SECRET,
      timestamp: TIMESTAMP,
    });
    // Canonical bytes IDENTICAL across orderings.
    expect(Array.from(signedA.rawBody)).toEqual(Array.from(signedB.rawBody));
    // Therefore signatures IDENTICAL.
    expect(signedA.headers["x-cealis-signature"]).toBe(signedB.headers["x-cealis-signature"]);
    // And cross-verification works: receiver bytes from A verify under B's
    // headers, proving the wire is byte-stable regardless of sender ordering.
    expect(
      verifyWebhookSignature({
        rawBody: signedA.rawBody,
        headers: signedB.headers,
        secret: SECRET,
        now: NOW,
      }),
    ).toBe(true);
  });
});

// ============================================================================
// Probe-2 — Nested-object key-order drift defended (recursive sort at every
//           level, where partner-emitted payloads live in `data`).
// ============================================================================
describe("Probe-2: nested-object key-order drift defended", () => {
  it("reordering inside data sub-object produces identical canonical bytes", () => {
    const envA = {
      event_id: "evt_nested",
      event_type: "g4.refused",
      schema_version: "s2-5.1",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: {
        authorizationId: "0xbb",
        reason_code: "0x02",
        reason_label: "Art18Restriction",
        retryable: false,
        nested: { a: 1, b: 2, c: 3 },
      },
    };
    const envB = {
      event_id: "evt_nested",
      event_type: "g4.refused",
      schema_version: "s2-5.1",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: {
        // sub-object keys reordered AND nested keys reordered
        nested: { c: 3, a: 1, b: 2 },
        retryable: false,
        reason_label: "Art18Restriction",
        reason_code: "0x02",
        authorizationId: "0xbb",
      },
    };
    const signedA = signWebhookEnvelope({
      envelope: { event_id: envA.event_id, event_type: envA.event_type },
      body: envA,
      secret: SECRET,
      timestamp: TIMESTAMP,
    });
    const signedB = signWebhookEnvelope({
      envelope: { event_id: envB.event_id, event_type: envB.event_type },
      body: envB,
      secret: SECRET,
      timestamp: TIMESTAMP,
    });
    expect(Array.from(signedA.rawBody)).toEqual(Array.from(signedB.rawBody));
    expect(signedA.headers["x-cealis-signature"]).toBe(signedB.headers["x-cealis-signature"]);
  });
});

// ============================================================================
// Probe-3 — Receiver-symmetry round-trip. Sign → verify against wire bytes
//           succeeds; wrong-secret fails; wrong-bytes fails. Pins that the
//           canonicalization doesn't break existing fail-paths.
// ============================================================================
describe("Probe-3: receiver-symmetry round-trip", () => {
  const envelope = {
    event_id: "evt_roundtrip",
    schema_version: "s2-5.1",
    event_type: "commit.finalized",
    created_at: "2026-05-21T10:00:00.000Z",
    partner_id: "partner_demo",
    pda_id: "pda_demo",
    data: { h_commit: "0xaa", status: "ok" },
  };
  const signed = signWebhookEnvelope({
    envelope: { event_id: envelope.event_id, event_type: envelope.event_type },
    body: envelope,
    secret: SECRET,
    timestamp: TIMESTAMP,
  });

  it("verify against the wire bytes succeeds", () => {
    expect(
      verifyWebhookSignature({
        rawBody: signed.rawBody,
        headers: signed.headers,
        secret: SECRET,
        now: NOW,
      }),
    ).toBe(true);
  });

  it("verify with wrong secret fails", () => {
    expect(
      verifyWebhookSignature({
        rawBody: signed.rawBody,
        headers: signed.headers,
        secret: "wrong_secret",
        now: NOW,
      }),
    ).toBe(false);
  });

  it("verify with tampered bytes fails", () => {
    // Flip one byte in the middle of the body.
    const tampered = new Uint8Array(signed.rawBody);
    if (tampered.length > 5) tampered[5] = tampered[5]! ^ 0xff;
    expect(
      verifyWebhookSignature({
        rawBody: tampered,
        headers: signed.headers,
        secret: SECRET,
        now: NOW,
      }),
    ).toBe(false);
  });
});

// ============================================================================
// Probe-4 — BigInt-in-envelope rejection (GATE-4 fail-closed).
//           A non-JCS-compatible value MUST throw the typed error, never
//           fall back to JSON.stringify (which would re-introduce the
//           canonicalization drift the fix closes).
// ============================================================================
describe("Probe-4: BigInt-in-envelope rejection (GATE-4 fail-closed)", () => {
  it("throws WebhookEnvelopeNotJcsCompatibleError on BigInt in data, never silently signs", () => {
    const envelope = {
      event_id: "evt_bigint",
      schema_version: "s2-5.1",
      event_type: "commit.finalized",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: {
        h_commit: "0xaa",
        amount: 42n, // BigInt — no JCS representation
      },
    };
    expect(() =>
      signWebhookEnvelope({
        envelope: { event_id: envelope.event_id, event_type: envelope.event_type },
        body: envelope,
        secret: SECRET,
        timestamp: TIMESTAMP,
      }),
    ).toThrow(WebhookEnvelopeNotJcsCompatibleError);
  });

  it("throws WebhookEnvelopeNotJcsCompatibleError on non-finite number, never silently signs", () => {
    const envelope = {
      event_id: "evt_nan",
      schema_version: "s2-5.1",
      event_type: "commit.finalized",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: { h_commit: "0xaa", price: Number.POSITIVE_INFINITY },
    };
    expect(() =>
      signWebhookEnvelope({
        envelope: { event_id: envelope.event_id, event_type: envelope.event_type },
        body: envelope,
        secret: SECRET,
        timestamp: TIMESTAMP,
      }),
    ).toThrow(WebhookEnvelopeNotJcsCompatibleError);
  });

  it("error carries Rule-47 safe_refs with cause type for diagnostics", () => {
    const envelope = {
      event_id: "evt_func",
      schema_version: "s2-5.1",
      event_type: "commit.finalized",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: { h_commit: "0xaa" },
    };
    let caught: unknown;
    try {
      signWebhookEnvelope({
        envelope: { event_id: envelope.event_id, event_type: envelope.event_type },
        body: { ...envelope, data: { ...envelope.data, bad: Symbol("x") as unknown } },
        secret: SECRET,
        timestamp: TIMESTAMP,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(WebhookEnvelopeNotJcsCompatibleError);
    const e = caught as WebhookEnvelopeNotJcsCompatibleError;
    expect(e.safeRefs.cause_name).toBeTruthy();
    expect(e.safeRefs.cause_message).toBeTruthy();
    expect(e.message).toMatch(/WEBHOOK_ENVELOPE_NOT_JCS_COMPATIBLE/);
  });
});

// ============================================================================
// Probe-5 — Undefined-field stripping behavior pinned. Per
//           bundle/canonicalize-jcs.ts:24-25 `toJcsValue` strips `undefined`
//           field values during recursion. Pin this so a future refactor
//           doesn't silently change the behavior.
// ============================================================================
describe("Probe-5: undefined-field stripping behavior pinned", () => {
  it("undefined-valued fields are stripped from canonical bytes", () => {
    const envelope = {
      event_id: "evt_undef",
      schema_version: "s2-5.1",
      event_type: "commit.finalized",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: { h_commit: "0xaa", optional_field: undefined as string | undefined },
    };
    const signed = signWebhookEnvelope({
      envelope: { event_id: envelope.event_id, event_type: envelope.event_type },
      body: envelope,
      secret: SECRET,
      timestamp: TIMESTAMP,
    });
    const decoded = new TextDecoder().decode(signed.rawBody);
    // The optional_field key should NOT appear in canonical bytes.
    expect(decoded).not.toContain("optional_field");
    // Other fields ARE present.
    expect(decoded).toContain("h_commit");
    expect(decoded).toContain("event_id");
  });

  it("envelope without the undefined field produces identical canonical bytes (stripping is equivalent to absence)", () => {
    const envWithUndef = {
      event_id: "evt_undef2",
      schema_version: "s2-5.1",
      event_type: "commit.finalized",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: { h_commit: "0xaa", optional: undefined as string | undefined },
    };
    const envWithoutUndef = {
      event_id: "evt_undef2",
      schema_version: "s2-5.1",
      event_type: "commit.finalized",
      created_at: "2026-05-21T10:00:00.000Z",
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: { h_commit: "0xaa" },
    };
    const signedA = signWebhookEnvelope({
      envelope: { event_id: envWithUndef.event_id, event_type: envWithUndef.event_type },
      body: envWithUndef,
      secret: SECRET,
      timestamp: TIMESTAMP,
    });
    const signedB = signWebhookEnvelope({
      envelope: { event_id: envWithoutUndef.event_id, event_type: envWithoutUndef.event_type },
      body: envWithoutUndef,
      secret: SECRET,
      timestamp: TIMESTAMP,
    });
    expect(Array.from(signedA.rawBody)).toEqual(Array.from(signedB.rawBody));
    expect(signedA.headers["x-cealis-signature"]).toBe(signedB.headers["x-cealis-signature"]);
  });
});
