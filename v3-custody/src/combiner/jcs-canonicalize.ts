import * as canonicalizeModule from "canonicalize";
import { keccak_256 } from "@noble/hashes/sha3";
import type { Hex32 } from "../m1-imports.js";

const canonicalizeJson = (canonicalizeModule as unknown as {
  readonly default: (input: unknown) => string | undefined;
}).default;

export type JcsValue =
  | null
  | boolean
  | number
  | string
  | readonly JcsValue[]
  | { readonly [key: string]: JcsValue };

export function jcsCanonicalize(value: JcsValue): Uint8Array {
  const encoded = canonicalizeJson(value);
  if (encoded === undefined) {
    throw new Error("JCS canonicalization failed");
  }
  return new TextEncoder().encode(encoded);
}

export function jcsDigest(value: JcsValue): Hex32 {
  return bytesToHex32(keccak_256(jcsCanonicalize(value)));
}

export function bytesToHex32(bytes: Uint8Array): Hex32 {
  if (bytes.length !== 32) {
    throw new Error(`expected 32 bytes, got ${bytes.length}`);
  }
  return bytesToHex(bytes) as Hex32;
}

export function bytesToHex(bytes: Uint8Array): `0x${string}` {
  let hex = "0x";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex as `0x${string}`;
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error("hex string must have an even number of nibbles");
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function asHex32(value: Uint8Array | Hex32): Hex32 {
  return typeof value === "string" ? value : bytesToHex32(value);
}

export function isZero32(value: Uint8Array): boolean {
  if (value.length !== 32) return false;
  let any = 0;
  for (const byte of value) any |= byte;
  return any === 0;
}

export function metadataString(
  metadata: Readonly<Record<string, string | number | bigint | Hex32>>,
  key: string,
): string | undefined {
  const value = metadata[key];
  return typeof value === "string" ? value : undefined;
}

export function metadataNumber(
  metadata: Readonly<Record<string, string | number | bigint | Hex32>>,
  key: string,
): number | undefined {
  const value = metadata[key];
  return typeof value === "number" ? value : undefined;
}

export function metadataBigint(
  metadata: Readonly<Record<string, string | number | bigint | Hex32>>,
  key: string,
): bigint | undefined {
  const value = metadata[key];
  return typeof value === "bigint" ? value : undefined;
}
