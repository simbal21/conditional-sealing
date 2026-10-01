import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "./pda-root.js";

export function canonicalizeJson(value: unknown): string {
  return serializeCanonical(value);
}

export function computeContentHash(template_spec: object): Uint8Array {
  return sha256(new TextEncoder().encode(canonicalizeJson(template_spec)));
}

export function computeContentHashHex(template_spec: object): `0x${string}` {
  return bytesToHex(computeContentHash(template_spec));
}

function serializeCanonical(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) throw new Error("contentHash: unsupported JSON value");
    return serialized;
  }
  if (Array.isArray(value)) return `[${value.map((entry) => serializeCanonical(entry)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${serializeCanonical(record[key])}`)
      .join(",")}}`;
  }
  throw new Error("contentHash: unsupported JSON value");
}
