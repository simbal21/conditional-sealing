import { keccak_256 } from "@noble/hashes/sha3";

import type { Hex32 } from "../m1-imports.js";
import { TAG_DCIPHER_IBE_BINDING_V3 } from "../m1-imports.js";

export interface DcipherIbeBindingInput {
  readonly networkId: string;
  readonly committeeId: string;
  readonly kemEpoch: bigint;
  readonly kemScope: string;
  readonly pdaRootDigest: Uint8Array;
  readonly authorizationId: Uint8Array;
  readonly commitContextDigest: Uint8Array;
  readonly stanzaIndex: 1;
  readonly shareDomain: "TOP_LEVEL";
  readonly shareRole: "G3";
  readonly x25519PubkeyDigest: Uint8Array;
  readonly mlkem768PubkeyDigest: Uint8Array;
  readonly x25519CiphersuiteId: string;
  readonly mlkemCiphersuiteId: string;
}

export function computeDcipherIbeBindingDigest(
  input: DcipherIbeBindingInput,
): Hex32 {
  assert32(input.pdaRootDigest, "pdaRootDigest");
  assert32(input.authorizationId, "authorizationId");
  assert32(input.commitContextDigest, "commitContextDigest");
  assert32(input.x25519PubkeyDigest, "x25519PubkeyDigest");
  assert32(input.mlkem768PubkeyDigest, "mlkem768PubkeyDigest");

  const digest = keccak_256(
    concatBytes([
      hexToBytes(TAG_DCIPHER_IBE_BINDING_V3),
      lengthPrefixedUtf8(input.networkId),
      lengthPrefixedUtf8(input.committeeId),
      uint64BE(input.kemEpoch),
      lengthPrefixedUtf8(input.kemScope),
      input.pdaRootDigest,
      input.authorizationId,
      input.commitContextDigest,
      new Uint8Array([input.stanzaIndex]),
      lengthPrefixedUtf8(input.shareDomain),
      lengthPrefixedUtf8(input.shareRole),
      input.x25519PubkeyDigest,
      input.mlkem768PubkeyDigest,
      lengthPrefixedUtf8(input.x25519CiphersuiteId),
      lengthPrefixedUtf8(input.mlkemCiphersuiteId),
    ]),
  );
  return bytesToHex32(digest);
}

function assert32(value: Uint8Array, name: string): void {
  if (value.length !== 32) {
    throw new Error(`${name} must be 32 bytes`);
  }
}

function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex32(bytes: Uint8Array): Hex32 {
  let hex = "0x";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex as Hex32;
}

function lengthPrefixedUtf8(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  return concatBytes([uint32BE(bytes.length), bytes]);
}

function uint32BE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

function uint64BE(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
