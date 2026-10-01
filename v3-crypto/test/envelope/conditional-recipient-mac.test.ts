import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildConditionalRecipientMacInput,
  computeConditionalRecipientMac,
  scaleCompactLengthPrefix,
} from "../../src/envelope/conditional-recipient-mac.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "envelope.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  conditional_mac: {
    mac_input_hex: string;
    mac: string;
  };
};

function bytes(seed: number, length = 32): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 23 + i * 13 + (seed ^ i)) & 0xff);
}

function bytesToHex(value: Uint8Array): string {
  return `0x${Array.from(value).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

describe("conditional-recipient MAC — §6.1.6", () => {
  it("golden vector is marked as locked Phase E seed", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase E seed");
  });

  it("builds variant/index/plugin/payload-bound MAC input", () => {
    const input = buildConditionalRecipientMacInput({
      variant_tag: 0x02,
      stanza_index: 3,
      plugin_version_digest: bytes(1),
      payload_bytes: new Uint8Array([0x02, 0xaa, 0xbb, 0xcc]),
    });
    expect(bytesToHex(input)).toBe(golden.conditional_mac.mac_input_hex);
    expect(bytesToHex(scaleCompactLengthPrefix(4))).toBe("0x10");
  });

  it("matches the locked MAC vector and changes when payload changes", () => {
    const base = {
      variant_tag: 0x02,
      stanza_index: 3,
      plugin_version_digest: bytes(1),
      payload_bytes: new Uint8Array([0x02, 0xaa, 0xbb, 0xcc]),
    };
    expect(bytesToHex(computeConditionalRecipientMac(base))).toBe(golden.conditional_mac.mac);
    expect(
      bytesToHex(computeConditionalRecipientMac({ ...base, payload_bytes: new Uint8Array([0x01, 0xaa, 0xbb, 0xcc]) })),
    ).not.toBe(golden.conditional_mac.mac);
  });

  it("rejects malformed fields", () => {
    expect(() =>
      buildConditionalRecipientMacInput({
        variant_tag: 0x100,
        stanza_index: 3,
        plugin_version_digest: bytes(1),
        payload_bytes: new Uint8Array([0x02]),
      }),
    ).toThrow("ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE");
    expect(() =>
      buildConditionalRecipientMacInput({
        variant_tag: 0x02,
        stanza_index: 3,
        plugin_version_digest: new Uint8Array(31),
        payload_bytes: new Uint8Array([0x02]),
      }),
    ).toThrow("ERR_CONDITIONAL_RECIPIENT_BYTES32_LENGTH");
  });
});
