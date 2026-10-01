import * as canonicalizeModule from "canonicalize";
import { keccak256, stringToBytes } from "viem";

export type Hex = `0x${string}`;
export type Hex32 = `0x${string}`;
export type PayloadCanonicalization = "jcs_json" | "raw_binary" | "multipart_file_part";

const canonicalizeJson = (canonicalizeModule as unknown as {
  readonly default: (input: unknown) => string | undefined;
}).default;

const HEX32_PATTERN = /^0x[0-9a-fA-F]{64}$/;

export function isHex32(value: unknown): value is Hex32 {
  return typeof value === "string" && HEX32_PATTERN.test(value);
}

export function assertHex32(value: unknown, field: string): asserts value is Hex32 {
  if (!isHex32(value)) {
    throw new Error(`${field} must be a 32-byte 0x-prefixed hex string`);
  }
}

export function normalizeHex32(value: Hex32): Hex32 {
  return `0x${value.slice(2).toLowerCase()}`;
}

export function hexToBytes32(value: Hex32): Uint8Array {
  assertHex32(value, "hex32");
  const out = new Uint8Array(32);
  const hex = value.slice(2);
  for (let i = 0; i < 32; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): Hex {
  let hex = "0x";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex as Hex;
}

export function bytesToHex32(bytes: Uint8Array): Hex32 {
  if (bytes.length !== 32) {
    throw new Error(`expected 32 bytes, got ${bytes.length}`);
  }
  return bytesToHex(bytes) as Hex32;
}

export function zeroHex32(): Hex32 {
  return "0x0000000000000000000000000000000000000000000000000000000000000000";
}

export function zeroBytes32(): Uint8Array {
  return new Uint8Array(32);
}

export function jcsCanonicalString(value: unknown): string {
  const encoded = canonicalizeJson(value);
  if (encoded === undefined) {
    throw new Error("JCS canonicalization failed");
  }
  return encoded;
}

export function jcsBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(jcsCanonicalString(value));
}

export function keccakHex32(bytes: Uint8Array): Hex32 {
  return normalizeHex32(keccak256(bytes) as Hex32);
}

export function jcsDigestHex32(value: unknown): Hex32 {
  return keccakHex32(jcsBytes(value));
}

export function utf8DigestHex32(value: string): Hex32 {
  return keccakHex32(stringToBytes(value));
}

export function bytesFromPayload(payload: unknown, canonicalization: PayloadCanonicalization): Uint8Array {
  if (canonicalization === "jcs_json") {
    return jcsBytes(payload);
  }
  if (canonicalization === "raw_binary") {
    if (typeof payload === "string") {
      return new TextEncoder().encode(payload);
    }
    if (payload instanceof Uint8Array) {
      return payload;
    }
    return jcsBytes(payload);
  }
  if (typeof payload === "string") {
    return new TextEncoder().encode(payload);
  }
  return jcsBytes(payload);
}

export function payloadDigestHex32(
  payload: unknown,
  canonicalization: PayloadCanonicalization,
): Hex32 {
  return keccakHex32(bytesFromPayload(payload, canonicalization));
}

