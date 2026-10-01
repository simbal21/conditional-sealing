import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  encodeShareRecord,
  decodeShareRecord,
  validateShareRecord,
  ShareRecordValidationError,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_ROLE_LIT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
  type ShareRecord,
  type ShareDomain,
  type ShareRole,
} from "../../src/codecs/share-record.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "share-record.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  vectors: Array<{
    name: string;
    record: { share_domain: number; share_role: number; logical_index: number; x: number; value: string };
    encoded_hex: string;
  }>;
  negative_vectors: Array<{
    name: string;
    record: { share_domain: number; share_role: number; logical_index: number; x: number; value_hex: string };
    expected_error: string;
  }>;
};

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("ShareRecord — §6.3.2 SCALE codec", () => {
  it("each record is 39 bytes", () => {
    for (const v of golden.vectors) {
      const rec: ShareRecord = {
        share_domain: v.record.share_domain as ShareDomain,
        share_role: v.record.share_role as ShareRole,
        logical_index: v.record.logical_index,
        x: v.record.x,
        value: hexBytes(v.record.value),
      };
      const encoded = encodeShareRecord(rec);
      expect(encoded.length).toBe(39);
    }
  });

  it("encode matches golden encoded_hex", () => {
    for (const v of golden.vectors) {
      const rec: ShareRecord = {
        share_domain: v.record.share_domain as ShareDomain,
        share_role: v.record.share_role as ShareRole,
        logical_index: v.record.logical_index,
        x: v.record.x,
        value: hexBytes(v.record.value),
      };
      expect(bytesToHex(encodeShareRecord(rec))).toBe(v.encoded_hex);
    }
  });

  it("decode round-trips encoded bytes", () => {
    for (const v of golden.vectors) {
      const decoded = decodeShareRecord(hexBytes(v.encoded_hex));
      expect(decoded.share_domain).toBe(v.record.share_domain);
      expect(decoded.share_role).toBe(v.record.share_role);
      expect(decoded.logical_index).toBe(v.record.logical_index);
      expect(decoded.x).toBe(v.record.x);
      expect(bytesToHex(decoded.value)).toBe(v.record.value);
    }
  });

  it("rejects x = 0 with ERR_SHAMIR_SHARE_INDEX_INVALID", () => {
    expect(() =>
      validateShareRecord({
        share_domain: SHARE_DOMAIN_TOP_LEVEL,
        share_role: SHARE_ROLE_LIT,
        logical_index: 0,
        x: 0,
        value: new Uint8Array(32),
      }),
    ).toThrow(ShareRecordValidationError);
  });

  it("rejects RECIPIENT_BRANCH + G4 with ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH (cross-domain substitution defense)", () => {
    expect(() =>
      validateShareRecord({
        share_domain: SHARE_DOMAIN_RECIPIENT_BRANCH,
        share_role: SHARE_ROLE_G4,
        logical_index: 0,
        x: 1,
        value: new Uint8Array(32),
      }),
    ).toThrow("ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH");
  });

  it("rejects TOP_LEVEL + CONDITIONAL_RECIPIENT", () => {
    expect(() =>
      validateShareRecord({
        share_domain: SHARE_DOMAIN_TOP_LEVEL,
        share_role: SHARE_ROLE_CONDITIONAL_RECIPIENT,
        logical_index: 0,
        x: 1,
        value: new Uint8Array(32),
      }),
    ).toThrow("ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH");
  });

  it("rejects wrong-length value", () => {
    expect(() =>
      validateShareRecord({
        share_domain: SHARE_DOMAIN_TOP_LEVEL,
        share_role: SHARE_ROLE_LIT,
        logical_index: 0,
        x: 1,
        value: new Uint8Array(31),
      }),
    ).toThrow("ERR_SHARE_RECORD_VALUE_LENGTH");
  });

  it("decode rejects wrong-length input", () => {
    expect(() => decodeShareRecord(new Uint8Array(38))).toThrow("ERR_SHARE_RECORD_DECODE_LENGTH");
    expect(() => decodeShareRecord(new Uint8Array(40))).toThrow("ERR_SHARE_RECORD_DECODE_LENGTH");
  });

  it("accepts all 4 TOP_LEVEL roles", () => {
    for (const role of [
      SHARE_ROLE_LIT,
      SHARE_ROLE_G3,
      SHARE_ROLE_G4,
      SHARE_ROLE_RECIPIENT_AGGREGATE,
    ]) {
      expect(() =>
        validateShareRecord({
          share_domain: SHARE_DOMAIN_TOP_LEVEL,
          share_role: role,
          logical_index: 0,
          x: 1,
          value: new Uint8Array(32),
        }),
      ).not.toThrow();
    }
  });
});
