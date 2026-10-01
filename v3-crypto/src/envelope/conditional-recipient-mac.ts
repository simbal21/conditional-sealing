import { keccak_256 } from "@noble/hashes/sha3";

import { TAG_CONDITIONAL_RECIPIENT_BINDING_V3, type Hex32 } from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";

export interface ConditionalRecipientMacInput {
  variant_tag: number;
  stanza_index: number;
  plugin_version_digest: Bytes32;
  payload_bytes: Bytes;
}

export const ConditionalRecipientMacError = {
  ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE: "ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE",
  ERR_CONDITIONAL_RECIPIENT_BYTES32_LENGTH: "ERR_CONDITIONAL_RECIPIENT_BYTES32_LENGTH",
} as const;

export type ConditionalRecipientMacErrorCode = keyof typeof ConditionalRecipientMacError;

export class ConditionalRecipientMacValidationError extends Error {
  constructor(
    public readonly code: ConditionalRecipientMacErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "ConditionalRecipientMacValidationError";
  }
}

function tagToBytes(tag: Hex32): Bytes32 {
  const hex = tag.slice(2);
  if (hex.length !== 64) {
    throw new ConditionalRecipientMacValidationError(
      "ERR_CONDITIONAL_RECIPIENT_BYTES32_LENGTH",
      "tag must be 32 bytes hex",
    );
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function assertU8(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new ConditionalRecipientMacValidationError(
      "ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE",
      `${field} must be uint8`,
    );
  }
}

function assertU32(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new ConditionalRecipientMacValidationError(
      "ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE",
      `${field} must be uint32`,
    );
  }
}

function assertBytes32(value: Bytes, field: string): void {
  if (value.length !== 32) {
    throw new ConditionalRecipientMacValidationError(
      "ERR_CONDITIONAL_RECIPIENT_BYTES32_LENGTH",
      `${field} must be 32 bytes, got ${value.length}`,
    );
  }
}

function u32BE(value: number): Bytes {
  assertU32(value, "stanza_index");
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

export function scaleCompactLengthPrefix(length: number): Bytes {
  if (!Number.isInteger(length) || length < 0 || length > 0x3fff_ffff) {
    throw new ConditionalRecipientMacValidationError(
      "ERR_CONDITIONAL_RECIPIENT_FIELD_RANGE",
      "SCALE compact length must be uint30",
    );
  }
  if (length < 1 << 6) return new Uint8Array([length << 2]);
  if (length < 1 << 14) {
    const value = (length << 2) | 0x01;
    return new Uint8Array([value & 0xff, (value >>> 8) & 0xff]);
  }
  const value = (length << 2) | 0x02;
  return new Uint8Array([
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  ]);
}

function concatBytes(...chunks: readonly Bytes[]): Bytes {
  const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let off = 0;
  for (const chunk of chunks) {
    out.set(chunk, off);
    off += chunk.length;
  }
  return out;
}

export function buildConditionalRecipientMacInput(input: ConditionalRecipientMacInput): Bytes {
  assertU8(input.variant_tag, "variant_tag");
  assertU32(input.stanza_index, "stanza_index");
  assertBytes32(input.plugin_version_digest, "plugin_version_digest");
  return concatBytes(
    new Uint8Array([input.variant_tag]),
    u32BE(input.stanza_index),
    input.plugin_version_digest,
    scaleCompactLengthPrefix(input.payload_bytes.length),
    input.payload_bytes,
  );
}

export function computeConditionalRecipientMac(input: ConditionalRecipientMacInput): Bytes32 {
  return keccak_256(
    concatBytes(tagToBytes(TAG_CONDITIONAL_RECIPIENT_BINDING_V3), buildConditionalRecipientMacInput(input)),
  );
}

export function conditionalRecipientMacEquals(a: Bytes32, b: Bytes32): boolean {
  assertBytes32(a, "a");
  assertBytes32(b, "b");
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
