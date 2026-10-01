// §2.4 + §4.3 salt-derivation signatures + REJECTION-SAMPLING contract.
//
// PHASE A LOCKED — MODULO REDUCTION IS FORBIDDEN FOR SALT→SCALAR.
//
// §2.4 lines 275-310 verbatim (NORMATIVE):
//
//   sd_salt_context_digest = keccak256(
//     TAG_SD_SALT_CONTEXT_V3
//     || authorizationId
//     || pda_root
//     || schema_digest
//     || partner_id
//     || sd_plan_digest
//   )
//
//   sd_master_salt = HKDF-SHA256(
//     salt = TAG_SD_SALT_V3 || sd_salt_context_digest,
//     ikm  = DEK,
//     info = "cealis-sd-master-salt-v3",
//     L    = 32
//   )
//
//   sd_field_salt_i = HKDF-SHA256(
//     salt = TAG_SD_SALT_V3 || authorizationId || field_id || field_index_u32_be,
//     ikm  = sd_master_salt,
//     info = "cealis-sd-field-salt-v3",
//     L    = 32
//   )
//
// §2.4 line 310 verbatim:
//   "The output is converted to a BN254 scalar with rejection sampling: if
//   OS2IP(output) >= p, expand with an appended counter byte in the HKDF
//   info string (...-v3/1, ...-v3/2, etc.) until the value is < p. Expected
//   retries are negligible because p is close to 2^254. Modulo reduction
//   is forbidden for salts because salt collisions would weaken binding."
//
// Phase A asserts:
//   - signature INCLUDES a counter-byte retry parameter
//   - phase B body MUST use the counter-byte HKDF info expansion (not modulo)
//   - SD-FIELD-004 vector (Phase E) exercises the retry path

import type { Bytes32 } from "../tags/preimages.js";
import type { BN254Scalar } from "./construction.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { TAG_SD } from "../tags/tags.js";
import { BN254_PRIME, bytes32, concatBytes, os2ip, u32be } from "../encoding/field-encoding.js";
import { SdError } from "../errors/sd-error.js";
import { SdErrorCode } from "../errors/codes.js";

export const HKDF_MASTER_INFO_PREFIX = "cealis-sd-master-salt-v3" as const;
export const HKDF_FIELD_INFO_PREFIX = "cealis-sd-field-salt-v3" as const;
export const SALT_OUTPUT_LENGTH_BYTES = 32 as const;

/**
 * `deriveSdSaltContextDigest` — §2.4 lines 280-287 + §D.7 lines 1832-1840.
 *
 * ACYCLIC by construction: input set is partner_id + pda_root + schema_digest
 * + authorizationId + sd_plan_digest. Does NOT consume sdMerkleRoot,
 * commit_AAD, aad_digest, commit_context_digest, or final h_commit (§2.4
 * line 297 + §D.7 line 1855).
 */
export interface DeriveSdSaltContextDigestInput {
  readonly authorizationId: Bytes32;
  readonly pda_root: Bytes32;
  readonly schema_digest: Bytes32;
  readonly partner_id: Bytes32;
  readonly sd_plan_digest: Bytes32;
}

export interface DeriveSdSaltContextDigest {
  (input: DeriveSdSaltContextDigestInput): Bytes32;
}

/**
 * `deriveSdMasterSalt` — §2.4 lines 289-294.
 *
 * Returns 32 bytes. Phase B body MUST zeroize the returned buffer after all
 * field salts are derived (§2.5 line 314).
 */
export interface DeriveSdMasterSalt {
  (dek: Uint8Array, sd_salt_context_digest: Bytes32): Uint8Array;
}

/**
 * `deriveSdFieldSalt` — §2.4 lines 302-307 + rejection-sampling §2.4 line 310.
 *
 * Returns a BN254 scalar. Phase B body implements rejection sampling via
 * counter-byte HKDF info expansion. Modulo reduction is FORBIDDEN.
 *
 * The `_retryCounter` parameter MUST be present in the signature — it
 * documents the rejection-sampling contract at the type level. Phase B
 * implementation starts at counter=0; if OS2IP(output) >= p, retries with
 * counter=1, 2, ... appending `/{counter}` to info string. Expected
 * retries are negligible per §2.4 line 310 because p ≈ 2^254.
 */
export interface DeriveSdFieldSaltInput {
  readonly sd_master_salt: Uint8Array;
  readonly authorizationId: Bytes32;
  readonly field_id: Bytes32;
  /** Encoded big-endian u32 at preimage time (§2.4 line 303). */
  readonly field_index: number;
}

export interface DeriveSdFieldSaltResult {
  readonly scalar: BN254Scalar;
  readonly salt_bytes: Uint8Array;
  readonly retry_count: number;
}

export interface DeriveSdFieldSalt {
  (input: DeriveSdFieldSaltInput): DeriveSdFieldSaltResult;
}

/**
 * `saltToBn254ScalarWithRejectionSampling` — explicit signature for the
 * NORMATIVE rejection-sampling primitive. Phase B body implements; SD-FIELD-004
 * test fixture exercises the retry path (synthetic HKDF output ≥ p forces ≥1
 * retry).
 *
 * `_retryCounter` is the loop counter; it MUST appear in the signature to
 * surface a TS compile error if Phase B accidentally drops it.
 *
 * Phase B body shape:
 *   let counter = 0;
 *   while (true) {
 *     const info = counter === 0
 *       ? HKDF_FIELD_INFO_PREFIX
 *       : `${HKDF_FIELD_INFO_PREFIX}/${counter}`;
 *     const out = hkdf_sha256(salt, ikm, info, 32);
 *     const candidate = os2ip(out);
 *     if (candidate < BN254_PRIME) return { scalar: candidate, salt_bytes: out, retry_count: counter };
 *     counter += 1;
 *     // expected retries ~= negligible — but loop bound enforced (e.g. 256)
 *   }
 */
export interface SaltToBn254ScalarWithRejectionSampling {
  (
    salt: Uint8Array,
    ikm: Uint8Array,
    base_info: string,
    out_len: number,
    _retryCounter: { readonly start_at: number; readonly max_retries: number },
  ): { readonly scalar: BN254Scalar; readonly salt_bytes: Uint8Array; readonly retry_count: number };
}

export function deriveSdSaltContextDigest(input: DeriveSdSaltContextDigestInput): Bytes32 {
  return keccak_256(
    concatBytes([
      TAG_SD.TAG_SD_SALT_CONTEXT_V3,
      bytes32(input.authorizationId, "authorizationId"),
      bytes32(input.pda_root, "pda_root"),
      bytes32(input.schema_digest, "schema_digest"),
      bytes32(input.partner_id, "partner_id"),
      bytes32(input.sd_plan_digest, "sd_plan_digest"),
    ]),
  );
}

export function deriveSdMasterSalt(dek: Uint8Array, sd_salt_context_digest: Bytes32): Uint8Array {
  try {
    return hkdf(
      sha256,
      dek,
      concatBytes([TAG_SD.TAG_SD_SALT_V3, bytes32(sd_salt_context_digest, "sd_salt_context_digest")]),
      utf8ToBytes(HKDF_MASTER_INFO_PREFIX),
      SALT_OUTPUT_LENGTH_BYTES,
    );
  } catch (cause) {
    throw new SdError(SdErrorCode.SALT_DERIVATION_FAIL, { stage: "salt_derivation", cause });
  }
}

export function deriveSdFieldSalt(input: DeriveSdFieldSaltInput): DeriveSdFieldSaltResult {
  return saltToBn254ScalarWithRejectionSampling(
    concatBytes([
      TAG_SD.TAG_SD_SALT_V3,
      bytes32(input.authorizationId, "authorizationId"),
      bytes32(input.field_id, "field_id"),
      u32be(input.field_index),
    ]),
    input.sd_master_salt,
    HKDF_FIELD_INFO_PREFIX,
    SALT_OUTPUT_LENGTH_BYTES,
    { start_at: 0, max_retries: 256 },
  );
}

export function saltToBn254ScalarWithRejectionSampling(
  salt: Uint8Array,
  ikm: Uint8Array,
  base_info: string,
  out_len: number,
  _retryCounter: { readonly start_at: number; readonly max_retries: number },
): { readonly scalar: BN254Scalar; readonly salt_bytes: Uint8Array; readonly retry_count: number } {
  for (let counter = _retryCounter.start_at; counter <= _retryCounter.max_retries; counter += 1) {
    const info = counter === 0 ? base_info : `${base_info}/${counter}`;
    let out: Uint8Array;
    try {
      out = hkdf(sha256, ikm, salt, utf8ToBytes(info), out_len);
    } catch (cause) {
      throw new SdError(SdErrorCode.SALT_DERIVATION_FAIL, { stage: "salt_derivation", cause });
    }
    const candidate = os2ip(out);
    if (candidate < BN254_PRIME) {
      return { scalar: candidate, salt_bytes: out, retry_count: counter - _retryCounter.start_at };
    }
  }
  throw new SdError(SdErrorCode.SALT_DERIVATION_FAIL, {
    stage: "salt_derivation",
    safeRefs: { code: SdErrorCode.SALT_DERIVATION_FAIL },
  });
}
