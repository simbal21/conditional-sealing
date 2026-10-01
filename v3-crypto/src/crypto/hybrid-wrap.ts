import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha256.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

import {
  TAG_STANZA_WRAP_NONCE_V3,
  TAG_STANZA_WRAP_V3,
  type Hex32,
} from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";
import type { ShareDomain, ShareRole } from "../codecs/share-record.js";

export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_SECRET_KEY_BYTES = 2400;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;
export const X25519_KEY_BYTES = 32;
export const WRAPPED_SHARE_PLAINTEXT_BYTES = 32;
export const WRAPPED_SHARE_BYTES = 48;
export const HYBRID_WRAP_PAYLOAD_BYTES =
  X25519_KEY_BYTES + ML_KEM_768_CIPHERTEXT_BYTES + WRAPPED_SHARE_BYTES;
export const HYBRID_WRAP_AAD_BYTES = 4 + 32 + 32 + 32 + 1 + 1 + 4 + 1;

export interface HybridWrapAADFields {
  stanza_index: number;
  binding_tag: Hex32;
  plugin_version_digest: Bytes32;
  commit_context_digest_N: Bytes32;
  share_domain: ShareDomain;
  share_role: ShareRole;
  logical_index: number;
  x: number;
}

export interface WrappedStanza {
  pk_eph_x25519: Bytes32;
  ct_mlkem: Bytes;
  wrapped_share: Bytes;
}

export interface HybridWrapRecipientPublicKeys {
  pk_x25519: Bytes32;
  pk_mlkem: Bytes;
}

export interface HybridWrapRecipientPrivateKeys extends HybridWrapRecipientPublicKeys {
  sk_x25519: Bytes32;
  sk_mlkem: Bytes;
}

export interface WrapShareForRecipientInput extends HybridWrapAADFields {
  recipient: HybridWrapRecipientPublicKeys;
  share: Bytes32;
  ephemeral_x25519_secret_key?: Bytes32;
  mlkem_encapsulation_seed?: Bytes;
}

export interface UnwrapShareForRecipientInput extends HybridWrapAADFields {
  recipient: HybridWrapRecipientPrivateKeys;
  wrapped: WrappedStanza;
}

export const HybridWrapError = {
  ERR_HYBRID_WRAP_FIELD_RANGE: "ERR_HYBRID_WRAP_FIELD_RANGE",
  ERR_HYBRID_WRAP_KEY_LENGTH: "ERR_HYBRID_WRAP_KEY_LENGTH",
  ERR_HYBRID_KEM_DECAPS_FAIL: "ERR_HYBRID_KEM_DECAPS_FAIL",
  ERR_STANZA_WRAP_AEAD_FAIL: "ERR_STANZA_WRAP_AEAD_FAIL",
} as const;

export type HybridWrapErrorCode = keyof typeof HybridWrapError;
export type HybridUnwrapResult =
  | { ok: true; share: Bytes32 }
  | { ok: false; error: HybridWrapErrorCode };

export class HybridWrapValidationError extends Error {
  constructor(
    public readonly code: HybridWrapErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "HybridWrapValidationError";
  }
}

function tagToBytes(tag: Hex32): Bytes32 {
  const hex = tag.slice(2);
  if (hex.length !== 64) {
    throw new HybridWrapValidationError("ERR_HYBRID_WRAP_KEY_LENGTH", "tag must be 32 bytes hex");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(...chunks: readonly Bytes[]): Bytes {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const chunk of chunks) {
    out.set(chunk, off);
    off += chunk.length;
  }
  return out;
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

function writeU32LE(out: Uint8Array, off: number, value: number): number {
  assertU32(value, "logical_index");
  out[off] = value & 0xff;
  out[off + 1] = (value >>> 8) & 0xff;
  out[off + 2] = (value >>> 16) & 0xff;
  out[off + 3] = (value >>> 24) & 0xff;
  return off + 4;
}

function assertU8(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new HybridWrapValidationError("ERR_HYBRID_WRAP_FIELD_RANGE", `${field} must be uint8`);
  }
}

function assertU32(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new HybridWrapValidationError("ERR_HYBRID_WRAP_FIELD_RANGE", `${field} must be uint32`);
  }
}

function assertLength(value: Bytes, expected: number, field: string): void {
  if (value.length !== expected) {
    throw new HybridWrapValidationError(
      "ERR_HYBRID_WRAP_KEY_LENGTH",
      `${field} must be ${expected} bytes, got ${value.length}`,
    );
  }
}

function validateAADFields(input: HybridWrapAADFields): void {
  assertU32(input.stanza_index, "stanza_index");
  assertLength(tagToBytes(input.binding_tag), 32, "binding_tag");
  assertLength(input.plugin_version_digest, 32, "plugin_version_digest");
  assertLength(input.commit_context_digest_N, 32, "commit_context_digest_N");
  assertU8(input.share_domain, "share_domain");
  assertU8(input.share_role, "share_role");
  assertU32(input.logical_index, "logical_index");
  assertU8(input.x, "x");
}

function validateRecipientPublicKeys(recipient: HybridWrapRecipientPublicKeys): void {
  assertLength(recipient.pk_x25519, X25519_KEY_BYTES, "pk_x25519");
  assertLength(recipient.pk_mlkem, ML_KEM_768_PUBLIC_KEY_BYTES, "pk_mlkem");
}

function validateRecipientPrivateKeys(recipient: HybridWrapRecipientPrivateKeys): void {
  validateRecipientPublicKeys(recipient);
  assertLength(recipient.sk_x25519, X25519_KEY_BYTES, "sk_x25519");
  assertLength(recipient.sk_mlkem, ML_KEM_768_SECRET_KEY_BYTES, "sk_mlkem");
}

export function encodeHybridWrapAAD(input: HybridWrapAADFields): Bytes {
  validateAADFields(input);
  const out = new Uint8Array(HYBRID_WRAP_AAD_BYTES);
  let off = 0;
  off = writeU32LE(out, off, input.stanza_index);
  out.set(tagToBytes(input.binding_tag), off);
  off += 32;
  out.set(input.plugin_version_digest, off);
  off += 32;
  out.set(input.commit_context_digest_N, off);
  off += 32;
  out[off++] = input.share_domain;
  out[off++] = input.share_role;
  off = writeU32LE(out, off, input.logical_index);
  out[off++] = input.x;
  return out;
}

export function encodeWrappedStanzaPayload(wrapped: WrappedStanza): Bytes {
  assertLength(wrapped.pk_eph_x25519, X25519_KEY_BYTES, "pk_eph_x25519");
  assertLength(wrapped.ct_mlkem, ML_KEM_768_CIPHERTEXT_BYTES, "ct_mlkem");
  assertLength(wrapped.wrapped_share, WRAPPED_SHARE_BYTES, "wrapped_share");
  return concatBytes(wrapped.pk_eph_x25519, wrapped.ct_mlkem, wrapped.wrapped_share);
}

export function decodeWrappedStanzaPayload(bytes: Bytes): WrappedStanza {
  if (bytes.length !== HYBRID_WRAP_PAYLOAD_BYTES) {
    throw new HybridWrapValidationError(
      "ERR_HYBRID_WRAP_KEY_LENGTH",
      `wrapped stanza payload must be ${HYBRID_WRAP_PAYLOAD_BYTES} bytes, got ${bytes.length}`,
    );
  }
  return {
    pk_eph_x25519: bytes.slice(0, 32),
    ct_mlkem: bytes.slice(32, 32 + ML_KEM_768_CIPHERTEXT_BYTES),
    wrapped_share: bytes.slice(32 + ML_KEM_768_CIPHERTEXT_BYTES),
  };
}

export function deriveStanzaWrapKey(input: {
  stanza_index: number;
  binding_tag: Hex32;
  commit_context_digest_N: Bytes32;
  recipient: HybridWrapRecipientPublicKeys;
  ss_x25519: Bytes32;
  ss_mlkem: Bytes32;
  pk_eph_x25519: Bytes32;
  ct_mlkem: Bytes;
}): Bytes32 {
  validateRecipientPublicKeys(input.recipient);
  assertLength(input.ss_x25519, 32, "ss_x25519");
  assertLength(input.ss_mlkem, 32, "ss_mlkem");
  assertLength(input.pk_eph_x25519, 32, "pk_eph_x25519");
  assertLength(input.ct_mlkem, ML_KEM_768_CIPHERTEXT_BYTES, "ct_mlkem");
  assertLength(input.commit_context_digest_N, 32, "commit_context_digest_N");

  const stanzaIndexBE = u32BE(input.stanza_index);
  return hkdf(
    sha256,
    concatBytes(input.ss_x25519, input.ss_mlkem, input.pk_eph_x25519, input.ct_mlkem),
    concatBytes(tagToBytes(TAG_STANZA_WRAP_V3), stanzaIndexBE, input.commit_context_digest_N),
    concatBytes(tagToBytes(input.binding_tag), input.recipient.pk_x25519, input.recipient.pk_mlkem),
    32,
  );
}

export function deriveStanzaWrapNonce(input: {
  stanza_wrap_key: Bytes32;
  stanza_index: number;
}): Bytes {
  assertLength(input.stanza_wrap_key, 32, "stanza_wrap_key");
  return hkdf(
    sha256,
    input.stanza_wrap_key,
    concatBytes(tagToBytes(TAG_STANZA_WRAP_NONCE_V3), u32BE(input.stanza_index)),
    new Uint8Array(),
    12,
  );
}

/**
 * Generate a hybrid-wrap recipient keypair (X25519 + ML-KEM-768). The PUBLIC
 * portion is the §6.2 wrap target; the PRIVATE portion is the gate's
 * enclave-resident unwrap key. Exposed so consumers (e.g. local gate-key stores,
 * Mode-B client SDKs) can mint per-commit gate keypairs without depending on
 * `@noble/post-quantum` directly. Optional `seeds` make it deterministic for
 * tests; production omits them and draws from the platform CSPRNG.
 */
export function generateHybridWrapRecipientKeypair(seeds?: {
  x25519_secret_key?: Bytes32;
  mlkem_seed?: Bytes;
}): HybridWrapRecipientPrivateKeys {
  const skX = seeds?.x25519_secret_key ?? x25519.utils.randomSecretKey();
  if (skX.length !== X25519_KEY_BYTES) {
    throw new HybridWrapValidationError("ERR_HYBRID_WRAP_KEY_LENGTH", "x25519 secret key must be 32 bytes");
  }
  const pkX = x25519.getPublicKey(skX);
  const ml = ml_kem768.keygen(seeds?.mlkem_seed ?? randomBytes(64));
  return {
    pk_x25519: pkX,
    pk_mlkem: ml.publicKey,
    sk_x25519: skX,
    sk_mlkem: ml.secretKey,
  };
}

export function wrapShareForRecipient(input: WrapShareForRecipientInput): WrappedStanza {
  validateAADFields(input);
  validateRecipientPublicKeys(input.recipient);
  assertLength(input.share, WRAPPED_SHARE_PLAINTEXT_BYTES, "share");
  if (input.ephemeral_x25519_secret_key !== undefined) {
    assertLength(input.ephemeral_x25519_secret_key, X25519_KEY_BYTES, "ephemeral_x25519_secret_key");
  }
  if (input.mlkem_encapsulation_seed !== undefined) {
    assertLength(input.mlkem_encapsulation_seed, 32, "mlkem_encapsulation_seed");
  }

  const skEph = input.ephemeral_x25519_secret_key ?? x25519.utils.randomSecretKey();
  const pkEph = x25519.getPublicKey(skEph);
  const ssX25519 = x25519.getSharedSecret(skEph, input.recipient.pk_x25519);
  const mlkem = ml_kem768.encapsulate(input.recipient.pk_mlkem, input.mlkem_encapsulation_seed ?? randomBytes(32));
  const stanzaWrapKey = deriveStanzaWrapKey({
    stanza_index: input.stanza_index,
    binding_tag: input.binding_tag,
    commit_context_digest_N: input.commit_context_digest_N,
    recipient: input.recipient,
    ss_x25519: ssX25519,
    ss_mlkem: mlkem.sharedSecret,
    pk_eph_x25519: pkEph,
    ct_mlkem: mlkem.cipherText,
  });
  const nonce = deriveStanzaWrapNonce({
    stanza_wrap_key: stanzaWrapKey,
    stanza_index: input.stanza_index,
  });
  const wrappedShare = chacha20poly1305(stanzaWrapKey, nonce, encodeHybridWrapAAD(input)).encrypt(input.share);

  return {
    pk_eph_x25519: pkEph,
    ct_mlkem: mlkem.cipherText,
    wrapped_share: wrappedShare,
  };
}

export function unwrapShareForRecipient(input: UnwrapShareForRecipientInput): HybridUnwrapResult {
  try {
    validateAADFields(input);
    validateRecipientPrivateKeys(input.recipient);
    assertLength(input.wrapped.pk_eph_x25519, X25519_KEY_BYTES, "pk_eph_x25519");
    assertLength(input.wrapped.ct_mlkem, ML_KEM_768_CIPHERTEXT_BYTES, "ct_mlkem");
    assertLength(input.wrapped.wrapped_share, WRAPPED_SHARE_BYTES, "wrapped_share");

    const ssX25519 = x25519.getSharedSecret(input.recipient.sk_x25519, input.wrapped.pk_eph_x25519);
    let ssMlkem: Bytes32;
    try {
      ssMlkem = ml_kem768.decapsulate(input.wrapped.ct_mlkem, input.recipient.sk_mlkem);
    } catch {
      return { ok: false, error: "ERR_HYBRID_KEM_DECAPS_FAIL" };
    }
    const stanzaWrapKey = deriveStanzaWrapKey({
      stanza_index: input.stanza_index,
      binding_tag: input.binding_tag,
      commit_context_digest_N: input.commit_context_digest_N,
      recipient: input.recipient,
      ss_x25519: ssX25519,
      ss_mlkem: ssMlkem,
      pk_eph_x25519: input.wrapped.pk_eph_x25519,
      ct_mlkem: input.wrapped.ct_mlkem,
    });
    const nonce = deriveStanzaWrapNonce({
      stanza_wrap_key: stanzaWrapKey,
      stanza_index: input.stanza_index,
    });
    const share = chacha20poly1305(stanzaWrapKey, nonce, encodeHybridWrapAAD(input)).decrypt(
      input.wrapped.wrapped_share,
    );
    if (share.length !== 32) return { ok: false, error: "ERR_STANZA_WRAP_AEAD_FAIL" };
    return { ok: true, share };
  } catch (error) {
    if (error instanceof HybridWrapValidationError) return { ok: false, error: error.code };
    return { ok: false, error: "ERR_STANZA_WRAP_AEAD_FAIL" };
  }
}
