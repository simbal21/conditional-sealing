import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha256.js";
import { keccak_256 } from "@noble/hashes/sha3";

import { encodeCommitAAD, type CommitAADInput } from "../codecs/commit-aad.js";
import { TAG_AEAD_V3, type Hex32 } from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";

export interface PayloadAEADBaseInput {
  dek: Bytes32;
  commit_context_digest_0: Bytes32;
  commit_AAD_v0: CommitAADInput;
}

export interface EncryptPayloadInput extends PayloadAEADBaseInput {
  plaintext: Bytes;
}

export interface DecryptPayloadInput extends PayloadAEADBaseInput {
  ciphertext: Bytes;
}

export interface EncryptPayloadOutput {
  ciphertext: Bytes;
  ciphertext_digest: Bytes32;
}

export const PayloadAEADError = {
  ERR_AEAD_FIELD_LENGTH: "ERR_AEAD_FIELD_LENGTH",
  ERR_AEAD_TRUNCATED_PAYLOAD: "ERR_AEAD_TRUNCATED_PAYLOAD",
  ERR_AEAD_TAG_VERIFY_FAIL: "ERR_AEAD_TAG_VERIFY_FAIL",
} as const;

export type PayloadAEADErrorCode = keyof typeof PayloadAEADError;
export type DecryptPayloadResult =
  | { ok: true; plaintext: Bytes }
  | { ok: false; error: PayloadAEADErrorCode };

export class PayloadAEADValidationError extends Error {
  constructor(
    public readonly code: PayloadAEADErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "PayloadAEADValidationError";
  }
}

function tagToBytes(tag: Hex32): Bytes32 {
  const hex = tag.slice(2);
  if (hex.length !== 64) {
    throw new PayloadAEADValidationError("ERR_AEAD_FIELD_LENGTH", "tag must be 32 bytes hex");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
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

function assertBytes32(value: Bytes, field: string): void {
  if (value.length !== 32) {
    throw new PayloadAEADValidationError(
      "ERR_AEAD_FIELD_LENGTH",
      `${field} must be 32 bytes, got ${value.length}`,
    );
  }
}

export function derivePayloadNonce(input: PayloadAEADBaseInput): Bytes {
  assertBytes32(input.dek, "dek");
  assertBytes32(input.commit_context_digest_0, "commit_context_digest_0");
  return hkdf(
    sha256,
    input.dek,
    concatBytes(tagToBytes(TAG_AEAD_V3), input.commit_context_digest_0),
    new Uint8Array(),
    12,
  );
}

export function encryptPayload(input: EncryptPayloadInput): EncryptPayloadOutput {
  const nonce = derivePayloadNonce(input);
  const aad = encodeCommitAAD(input.commit_AAD_v0);
  const ciphertext = chacha20poly1305(input.dek, nonce, aad).encrypt(input.plaintext);
  return {
    ciphertext,
    ciphertext_digest: keccak_256(ciphertext),
  };
}

export function decryptPayload(input: DecryptPayloadInput): DecryptPayloadResult {
  try {
    assertBytes32(input.dek, "dek");
    assertBytes32(input.commit_context_digest_0, "commit_context_digest_0");
    if (input.ciphertext.length < 16) return { ok: false, error: "ERR_AEAD_TRUNCATED_PAYLOAD" };
    const nonce = derivePayloadNonce(input);
    const aad = encodeCommitAAD(input.commit_AAD_v0);
    return {
      ok: true,
      plaintext: chacha20poly1305(input.dek, nonce, aad).decrypt(input.ciphertext),
    };
  } catch (error) {
    if (error instanceof PayloadAEADValidationError) return { ok: false, error: error.code };
    return { ok: false, error: "ERR_AEAD_TAG_VERIFY_FAIL" };
  }
}
