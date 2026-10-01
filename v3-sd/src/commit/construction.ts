// Per-field Poseidon commitment construction — Phase A signatures only.
//
// §4.1 lines 420-428 VERBATIM (byte-exact canonical citation site):
//
//   field_commitment = Poseidon5(
//     tag_field_scalar,
//     authorization_scalar,
//     field_id_scalar,
//     salt_field_scalar,
//     value_scalar
//   )
//
// Where (§4.1 lines 432-436 verbatim):
//   - tag_field_scalar       = OS2IP(TAG_SD_FIELD_V3) mod p
//   - authorization_scalar   = OS2IP(authorizationId) mod p
//   - field_id_scalar        = OS2IP(field_id) mod p
//   - salt_field_scalar      = rejection-sampled per-field salt scalar (§2.4)
//   - value_scalar           = canonical scalar encoding of field value (§4.2)
//
// The commitment output is a BN254 scalar. EVM-facing bundles encode it as
// `uint256` constrained to `< p` (§4.1 line 438).
//
// NOTE: line 1325 is a §7.2 circuit-constraint USAGE site (§A.1 equality
// circuit pseudocode) that re-uses the same form — fine for cross-reference,
// NOT the canonical byte-exact citation. The §4.1 definition site at lines
// 420-428 is the load-bearing source per SPEC-COMPLIANCE-GUARD-M6 §4.

import { createRequire } from "node:module";

import type { Bytes32 } from "../tags/preimages.js";
import { TAG_SD } from "../tags/tags.js";
import { BN254_PRIME, assertBn254Scalar, os2ip, scalarFromBytesMod } from "../encoding/field-encoding.js";
import { SdError } from "../errors/sd-error.js";
import { SdErrorCode } from "../errors/codes.js";

/** BN254 scalar — opaque to Phase A; Phase B types via @noble/curves field. */
export type BN254Scalar = bigint;

/**
 * Phase A SIGNATURE-ONLY input shape for per-field commitment construction.
 * Phase B fills body in `src/commit/construction.ts` of this file (Phase B
 * extends, does not replace).
 *
 * Inputs are scalars (already reduced mod p) so the construction is
 * cryptographic-grade unambiguous.
 */
export interface FieldCommitmentInput {
  readonly tag_field_scalar: BN254Scalar;
  readonly authorization_scalar: BN254Scalar;
  readonly field_id_scalar: BN254Scalar;
  readonly salt_field_scalar: BN254Scalar;
  readonly value_scalar: BN254Scalar;
}

export interface FieldCommitmentInputBytes {
  readonly authorizationId: Bytes32;
  readonly field_id: Bytes32;
  readonly field_salt_bytes: Uint8Array;
  /** Canonical scalar encoding of the field value per §4.2. */
  readonly value_scalar_encoded_bytes: Uint8Array;
}

/**
 * Phase B body computes:
 *
 *   field_commitment = Poseidon5(
 *     tag_field_scalar,        // OS2IP(TAG_SD_FIELD_V3) mod p
 *     authorization_scalar,    // OS2IP(authorizationId) mod p
 *     field_id_scalar,         // OS2IP(field_id) mod p
 *     salt_field_scalar,       // rejection-sampled scalar
 *     value_scalar             // canonical scalar per §4.2
 *   )
 *
 * Output: BN254 scalar `< p`.
 */
export interface ComputeFieldCommitment {
  (input: FieldCommitmentInput): BN254Scalar;
}

/**
 * High-level builder: takes byte-level inputs, derives scalars via OS2IP
 * + rejection sampling for salt, and returns the field_commitment scalar.
 * Phase B fills body; Phase E SDK uses this signature for off-chain
 * recomputation during verifyClaim.
 */
export interface BuildFieldCommitmentFromBytes {
  (input: FieldCommitmentInputBytes): BN254Scalar;
}

type PoseidonFn = ((inputs: ReadonlyArray<bigint>) => Uint8Array) & {
  F: { toObject(value: Uint8Array): bigint };
};

const require = createRequire(import.meta.url);
const { buildPoseidon } = require("circomlibjs") as { buildPoseidon: () => Promise<PoseidonFn> };
const poseidon: PoseidonFn = await buildPoseidon();

export function computeFieldCommitment(input: FieldCommitmentInput): BN254Scalar {
  const scalars = [
    input.tag_field_scalar,
    input.authorization_scalar,
    input.field_id_scalar,
    input.salt_field_scalar,
    input.value_scalar,
  ];
  for (const scalar of scalars) assertBn254Scalar(scalar);
  try {
    const out = poseidon(scalars);
    const scalar = poseidon.F.toObject(out);
    assertBn254Scalar(scalar);
    return scalar;
  } catch (cause) {
    throw new SdError(SdErrorCode.COMMITMENT_MISMATCH, { stage: "commitment_build", cause });
  }
}

export function buildFieldCommitmentFromBytes(input: FieldCommitmentInputBytes): BN254Scalar {
  const saltScalar = os2ip(input.field_salt_bytes);
  if (saltScalar >= BN254_PRIME) {
    throw new SdError(SdErrorCode.SALT_DERIVATION_FAIL, { stage: "salt_derivation" });
  }
  return computeFieldCommitment({
    tag_field_scalar: scalarFromBytesMod(TAG_SD.TAG_SD_FIELD_V3),
    authorization_scalar: scalarFromBytesMod(input.authorizationId),
    field_id_scalar: scalarFromBytesMod(input.field_id),
    salt_field_scalar: saltScalar,
    value_scalar: scalarFromBytesMod(input.value_scalar_encoded_bytes),
  });
}
