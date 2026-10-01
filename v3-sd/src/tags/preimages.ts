// SD byte-preimage shapes per S2-7 §3.3 lines 353-407 (verbatim normative).
//
// This file exports TS-side type aliases + Phase B/E will fill body algorithms
// that build these preimages. Phase A locks the shapes so cross-chunk drift
// surfaces at TS compile.
//
// Preimage construction is normative; every multi-byte integer is BIG-ENDIAN
// (§3.3 line 406). Variable-length Claim ASTs are canonicalized + hashed to
// fixed-width digests before entering preimages.
//
// VERBATIM normative blocks from §3.3 lines 357-401:
//
//   sd_bundle_digest = keccak256(
//     TAG_SD_COMMIT_V3
//     || authorizationId
//     || h_commit
//     || pda_root
//     || partner_id
//     || sdMerkleRoot
//     || sd_salt_context_digest
//     || sd_plan_digest
//   )
//
//   claim_id = keccak256(
//     TAG_SD_CLAIM_V3
//     || partner_id
//     || pda_id
//     || pda_version_u64_be
//     || claim_index_u32_be
//     || claim_ast_digest
//   )
//
//   proof_context_digest = keccak256(
//     TAG_SD_PROOF_V3
//     || authorizationId
//     || h_commit
//     || partner_id
//     || pda_id
//     || claim_id
//     || verifier_ref
//     || expiry_timestamp_u64_be
//   )
//
//   nullifier = keccak256(
//     TAG_SD_NULLIFIER_V3
//     || authorizationId
//     || partner_id
//     || claim_id
//     || field_id
//   )
//
// `disclosure_id` is the unified Claim-proof policy handle (collapsed from
// prior `revocation_id`/`disclosure_id` split per Phase 2b H-1). Per §D.6
// lines 1818-1825:
//
//   disclosure_id = keccak256(
//     TAG_SD_COMMIT_V3
//     || authorizationId
//     || claim_id
//     || proof_context_digest
//     || proof_digest
//   )
//
// where `proof_digest = keccak256(proof_bytes)`.
//
// PHASE A NOTE: this file declares the input shapes. Algorithm bodies live in
// `src/commit/`, `src/sd-plan/`, and SDK (`sdk/src/verify-*.ts`) — Phase B/E.

export type Bytes32 = Uint8Array;
export type Bytes20 = Uint8Array;

/** Inputs to `sd_bundle_digest` per §3.3 + §5.4 (lines 543-553). */
export interface SdBundleDigestInputs {
  readonly authorizationId: Bytes32;
  readonly h_commit: Bytes32;
  readonly pda_root: Bytes32;
  readonly partner_id: Bytes32;
  /** BN254 scalar serialized as 32-byte big-endian per §D.7 line 1855. */
  readonly sdMerkleRoot: Bytes32;
  readonly sd_salt_context_digest: Bytes32;
  readonly sd_plan_digest: Bytes32;
}

/** Inputs to `claim_id` per §3.3 lines 371-379. */
export interface ClaimIdInputs {
  readonly partner_id: Bytes32;
  readonly pda_id: Bytes32;
  /** Encoded big-endian u64 at preimage time. */
  readonly pda_version: bigint;
  /** Encoded big-endian u32 at preimage time. */
  readonly claim_index: number;
  readonly claim_ast_digest: Bytes32;
}

/** Inputs to `proof_context_digest` per §3.3 lines 382-391. */
export interface ProofContextDigestInputs {
  readonly authorizationId: Bytes32;
  readonly h_commit: Bytes32;
  readonly partner_id: Bytes32;
  readonly pda_id: Bytes32;
  readonly claim_id: Bytes32;
  readonly verifier_ref: Bytes32;
  /** Encoded big-endian u64 at preimage time. */
  readonly expiry_timestamp: bigint;
}

/** Inputs to `nullifier` per §3.3 lines 394-401. */
export interface NullifierInputs {
  readonly authorizationId: Bytes32;
  readonly partner_id: Bytes32;
  readonly claim_id: Bytes32;
  readonly field_id: Bytes32;
}

/**
 * Inputs to `disclosure_id` per §D.6 lines 1818-1825 (unified Claim-proof
 * policy handle, post-Phase-2b H-1 collapse).
 */
export interface DisclosureIdInputs {
  readonly authorizationId: Bytes32;
  readonly claim_id: Bytes32;
  readonly proof_context_digest: Bytes32;
  /** `keccak256(proof_bytes)` per §D.6 line 1827. */
  readonly proof_digest: Bytes32;
}

/**
 * Inputs to `sd_salt_context_digest` per §2.4 lines 280-287 + §D.7.
 *
 * NORMATIVE acyclic: does NOT consume `sdMerkleRoot`, `commit_AAD`,
 * `aad_digest`, `commit_context_digest`, or final `h_commit`. §2.4 line 297
 * + §D.7 line 1855.
 */
export interface SdSaltContextDigestInputs {
  readonly authorizationId: Bytes32;
  readonly pda_root: Bytes32;
  readonly schema_digest: Bytes32;
  readonly partner_id: Bytes32;
  readonly sd_plan_digest: Bytes32;
}

/**
 * Inputs to `field_id` per §1.1 lines 134-145.
 *
 *   field_id = keccak256(
 *     TAG_SD_FIELD_ID_V3
 *     || schema_digest
 *     || field_path_hash
 *     || field_type_code
 *   )
 */
export interface FieldIdInputs {
  readonly schema_digest: Bytes32;
  readonly field_path_hash: Bytes32;
  /**
   * Single byte canonical type family. §1.1 line 145 verbatim:
   *   0x01 string, 0x02 uint, 0x03 int, 0x04 bool, 0x05 bytes,
   *   0x06 date, 0x07 decimal_fixed, 0x08 enum, 0x09 country_code,
   *   0x0A address, 0x0B object_hash.
   */
  readonly field_type_code: number;
}

/**
 * Inputs to `verifier_ref` per §7.1 lines 720-728 (verbatim normative).
 *
 *   verifier_ref = keccak256(
 *     TAG_SD_VERIFIER_V3
 *     || circuit_family_id
 *     || circuit_version_u32_be
 *     || verification_key_digest
 *     || public_input_schema_digest
 *   )
 */
export interface VerifierRefInputs {
  readonly circuit_family_id: Bytes32;
  /** u32 big-endian at preimage time. */
  readonly circuit_version: number;
  readonly verification_key_digest: Bytes32;
  readonly public_input_schema_digest: Bytes32;
}
