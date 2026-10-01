// App. I.3 `SdClaimConfig` — per-Claim configuration record. Verbatim
// from §App.I lines 2221-2233.
//
// CLAIM TYPE CODE LOCK (§I.3 line 2224 + §6.6):
//   1 = range, 2 = equality, 3 = set, 4 = non_equality, 5 = composed

import type { Bytes32 } from "../tags/preimages.js";

export const CLAIM_TYPE_CODE = {
  RANGE: 1,
  EQUALITY: 2,
  SET_MEMBERSHIP: 3,
  NON_EQUALITY: 4,
  COMPOSED: 5,
} as const;

export type ClaimTypeCode = typeof CLAIM_TYPE_CODE[keyof typeof CLAIM_TYPE_CODE];

/**
 * SCALE-shaped Claim config record.
 *
 *   struct SdClaimConfig {
 *     claim_index:                        u32,
 *     claim_id:                           [u8; 32],
 *     claim_type:                         u8,
 *     expression_digest:                  [u8; 32],
 *     field_ids_root:                     [u8; 32],
 *     verifier_policy_ref:                [u8; 32],
 *     expiry_seconds:                     u64,
 *     public_verifiable:                  bool,
 *     on_chain_registration_required:     bool,
 *     revocation_required:                bool,
 *     partner_decision_critical:          bool
 *   }
 */
export interface SdClaimConfig {
  readonly claim_index: number;
  readonly claim_id: Bytes32;
  readonly claim_type: ClaimTypeCode;
  readonly expression_digest: Bytes32;
  readonly field_ids_root: Bytes32;
  readonly verifier_policy_ref: Bytes32;
  readonly expiry_seconds: bigint;
  /** §I.3 line 2238: must be false unless `SdPlan.public_composability_allowed = true`. */
  readonly public_verifiable: boolean;
  readonly on_chain_registration_required: boolean;
  /** Claim-proof policy flag — does NOT create field/cleartext revocation handles (§I.3 line 2240). */
  readonly revocation_required: boolean;
  /** Partner-decision-critical flag — failure surfaces partial SD status (§I.3 line 2236). */
  readonly partner_decision_critical: boolean;
}
