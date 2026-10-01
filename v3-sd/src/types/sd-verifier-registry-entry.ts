// App. I.10 `SdVerifierRegistryEntry` — verifier registry record. Verbatim
// from §App.I lines 2357-2371.
//
// The registry entry stores DIGESTS, not proving keys or verification keys.
// Full artifacts are distributed through S2-6-controlled artifact channels
// (§I.10 line 2374).

import type { Bytes32, Bytes20 } from "../tags/preimages.js";

/**
 *   struct SdVerifierRegistryEntry {
 *     verifier_ref:                       [u8; 32],
 *     circuit_family_id:                  [u8; 32],
 *     circuit_version:                    u32,
 *     verifier_contract:                  [u8; 20],
 *     verification_key_digest:            [u8; 32],
 *     proving_key_digest:                 [u8; 32],
 *     setup_transcript_digest:            [u8; 32],
 *     public_input_schema_digest:         [u8; 32],
 *     max_tree_depth:                     u8,
 *     max_public_inputs:                  u16,
 *     effective_block:                    u64,
 *     tombstone_block:                    u64,
 *     deprecation_flag_digest:            [u8; 32]
 *   }
 */
export interface SdVerifierRegistryEntry {
  readonly verifier_ref: Bytes32;
  readonly circuit_family_id: Bytes32;
  readonly circuit_version: number;
  /**
   * `verifier_contract` may be 20 zero bytes for off-chain-only verifier refs;
   * partner SDKs can still resolve verification keys off-chain through
   * S2-3/S2-6 metadata (§I.10 line 2374).
   */
  readonly verifier_contract: Bytes20;
  readonly verification_key_digest: Bytes32;
  readonly proving_key_digest: Bytes32;
  readonly setup_transcript_digest: Bytes32;
  readonly public_input_schema_digest: Bytes32;
  readonly max_tree_depth: number;
  readonly max_public_inputs: number;
  readonly effective_block: bigint;
  readonly tombstone_block: bigint;
  readonly deprecation_flag_digest: Bytes32;
}
