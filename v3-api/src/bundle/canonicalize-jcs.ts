import {
  jcsCanonicalize as m3JcsCanonicalize,
  jcsDigest as m3JcsDigest,
  type JcsValue,
} from "../m3-imports.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

const textDecoder = new TextDecoder();

export { type JcsValue };

export function toJcsValue(value: unknown): JcsValue {
  if (value === null) return null;
  if (typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("JCS value cannot contain non-finite numbers.");
    }
    return value;
  }
  if (Array.isArray(value)) return value.map((item) => toJcsValue(item));
  if (typeof value === "object") {
    const out: Record<string, JcsValue> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      if (inner === undefined) continue;
      out[key] = toJcsValue(inner);
    }
    return out;
  }
  throw new Error(`JCS value cannot contain ${typeof value}.`);
}

export function canonicalizeJcs(value: unknown): Uint8Array {
  return m3JcsCanonicalize(toJcsValue(value));
}

export function canonicalizeJcsString(value: unknown): string {
  return textDecoder.decode(canonicalizeJcs(value));
}

export function jcsDigest(value: unknown): Hex32 {
  return m3JcsDigest(toJcsValue(value)) as Hex32;
}
