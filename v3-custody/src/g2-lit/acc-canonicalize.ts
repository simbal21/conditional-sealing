import { keccak_256 } from "@noble/hashes/sha3";
import type { Hex32 } from "@cealis/v3-crypto";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { readonly [key: string]: JsonValue };

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function canonicalizeAcc(input: JsonValue): Uint8Array {
  return textEncoder.encode(canonicalizeAccString(input));
}

export function canonicalizeAccString(input: JsonValue): string {
  return stringifyCanonical(normalizeJson(input));
}

export function parseCanonicalAccBytes(bytes: Uint8Array): JsonValue {
  return JSON.parse(textDecoder.decode(bytes)) as JsonValue;
}

export function litAccBindingDigest(canonicalAccBytes: Uint8Array, tag: Hex32): Uint8Array {
  return keccak_256(concatBytes([hexToBytes(tag), canonicalAccBytes]));
}

export function litAccBindingDigestHex(canonicalAccBytes: Uint8Array, tag: Hex32): Hex32 {
  return bytesToHex(litAccBindingDigest(canonicalAccBytes, tag));
}

export function keccakHex(parts: readonly Uint8Array[]): Hex32 {
  return bytesToHex(keccak_256(concatBytes(parts)));
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const len = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length === 0) return new Uint8Array(0);
  if (stripped.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex (${stripped.length})`);
  }
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("hexToBytes: non-hex input");
    out[i] = byte;
  }
  return out;
}

export function hexToBytes32(hex: Hex32 | string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) {
    throw new Error(`hexToBytes32: expected 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): Hex32 {
  let out = "0x";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out as Hex32;
}

export function assertHex32(value: string, name: string): asserts value is Hex32 {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${name} must be 0x-prefixed 32-byte hex`);
  }
}

function normalizeJson(value: JsonValue): JsonValue {
  if (value === null) return value;
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical ACC cannot encode non-finite numbers");
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => normalizeJson(entry));

  const out: Record<string, JsonValue> = {};
  for (const key of Object.keys(value).sort()) {
    const raw = value[key];
    if (raw === undefined) throw new Error(`canonical ACC cannot encode undefined at key ${key}`);
    out[key] = normalizeJson(raw);
  }
  return out;
}

function stringifyCanonical(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stringifyCanonical(entry)).join(",")}]`;
  }
  const entries = Object.entries(value);
  return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${stringifyCanonical(entry)}`).join(",")}}`;
}
