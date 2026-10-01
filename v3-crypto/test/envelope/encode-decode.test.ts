import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decodeAgeEnvelope,
  verifyEnvelopeStanzaMacs,
} from "../../src/envelope/decode.js";
import { encodeAgeEnvelope } from "../../src/envelope/encode.js";
import {
  TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
  TAG_G4_ATTESTATION_AUTHORITY_V3,
  TAG_LIT_ACC_BINDING_V3,
} from "../../src/tags.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "envelope.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  encode_decode: {
    encoded_hex: string;
  };
};

function bytes(seed: number, length = 32): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 19 + i * 5 + (seed ^ i)) & 0xff);
}

function bytesToHex(value: Uint8Array): string {
  return `0x${Array.from(value).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function fixtureEnvelope(): Uint8Array {
  return encodeAgeEnvelope({
    stanzas: [
      {
        stanza_index: 0,
        binding_tag: TAG_LIT_ACC_BINDING_V3,
        plugin_version_digest: bytes(1),
        ciphertext_payload_bytes: new Uint8Array([0x10, 0x11]),
      },
      {
        stanza_index: 2,
        binding_tag: TAG_G4_ATTESTATION_AUTHORITY_V3,
        plugin_version_digest: bytes(1),
        ciphertext_payload_bytes: new Uint8Array([0x20, 0x21, 0x22]),
      },
      {
        stanza_index: 3,
        binding_tag: TAG_CONDITIONAL_RECIPIENT_BINDING_V3,
        plugin_version_digest: bytes(1),
        ciphertext_payload_bytes: new Uint8Array([0x02, 0x30, 0x31, 0x32]),
      },
    ],
    payload_ciphertext: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
  });
}

describe("age envelope encode/decode — §6.1", () => {
  it("matches locked SCALE envelope bytes", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase E seed");
    expect(bytesToHex(fixtureEnvelope())).toBe(golden.encode_decode.encoded_hex);
  });

  it("round-trips stanzas and payload", () => {
    const decoded = decodeAgeEnvelope(fixtureEnvelope());
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) throw new Error(decoded.error);
    expect(decoded.stanzas).toHaveLength(3);
    expect(decoded.payload_ciphertext).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]));
    expect(verifyEnvelopeStanzaMacs(decoded).ok).toBe(true);
  });

  it("strictly rejects truncated stanza bytes", () => {
    const encoded = fixtureEnvelope();
    expect(decodeAgeEnvelope(encoded.slice(0, 10))).toEqual({ ok: false, error: "ERR_STANZA_LENGTH_INVALID" });
  });

  it("detects gate stanza MAC tampering", () => {
    const encoded = fixtureEnvelope();
    const decoded = decodeAgeEnvelope(encoded);
    if (!decoded.ok) throw new Error(decoded.error);
    decoded.stanzas[0]!.mac[0]! ^= 0x01;
    expect(verifyEnvelopeStanzaMacs(decoded)).toEqual({ ok: false, error: "ERR_GATE_STANZA_MAC_FAIL" });
  });

  it("detects conditional-recipient MAC tampering before payload parse", () => {
    const encoded = fixtureEnvelope();
    const decoded = decodeAgeEnvelope(encoded);
    if (!decoded.ok) throw new Error(decoded.error);
    decoded.stanzas[2]!.ciphertext_payload_bytes[0]! ^= 0x01;
    expect(verifyEnvelopeStanzaMacs(decoded)).toEqual({
      ok: false,
      error: "ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL",
    });
  });
});
