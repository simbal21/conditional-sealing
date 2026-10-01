// App. I.11 `SdRevocationRecord` — revocation policy record. Verbatim from
// §App.I lines 2379-2391.
//
// PRIVACY DEFAULT (§I.11 line 2394 NORMATIVE):
//   "The default event indexes `disclosure_id`, `authorizationId`, and
//   `claim_id` per §11.2 — never `subject_commitment_v3`."
//
// M2 (`contracts/src/disclosure/DisclosureRevocationRegistry.sol`)
// already ships with this default. M6 Phase E adds a NEGATIVE TEST asserting
// `subject_commitment_v3` is absent from `DisclosureRevoked` event topics and
// data, and Phase F tripwire grep `grep -rnE "subject_commitment_v3"` flags
// any active-code reintroduction.
//
// SdRevocationRecord is claim-shaped by design (§I.11 line 2396). It records
// policy invalidation for Claim proofs and registered disclosure ids. It is
// NOT a field-commitment revocation record and does NOT revoke cleartext
// outputs already delivered to a partner.

import type { Bytes32, Bytes20 } from "../tags/preimages.js";

/**
 *   struct SdRevocationRecord {
 *     disclosure_id:                      [u8; 32],
 *     authorizationId:                    [u8; 32],
 *     partner_id:                         [u8; 32],
 *     claim_id:                           [u8; 32],
 *     subject_commitment_v3:              [u8; 32],
 *     authorized_revoker:                 [u8; 20],
 *     revoked:                            bool,
 *     reason_code:                        u8,
 *     evidence_ref:                       [u8; 32],
 *     revoked_at_block:                   u64,
 *     revoked_at_timestamp:               u64
 *   }
 *
 * NOTE: `subject_commitment_v3` is part of the STORAGE record per spec, but
 * is NOT emitted in the default `DisclosureRevoked` event (M2 line 27). PIIs
 * remain pseudonymous but still treated as personal-data-adjacent.
 */
export interface SdRevocationRecord {
  readonly disclosure_id: Bytes32;
  readonly authorizationId: Bytes32;
  readonly partner_id: Bytes32;
  readonly claim_id: Bytes32;
  readonly subject_commitment_v3: Bytes32;
  readonly authorized_revoker: Bytes20;
  readonly revoked: boolean;
  readonly reason_code: number;
  readonly evidence_ref: Bytes32;
  readonly revoked_at_block: bigint;
  readonly revoked_at_timestamp: bigint;
}

/**
 * §11.5 lines 1099-1106 — 6-row revocation reason codes (verbatim).
 *
 * `0x07+` is unmapped (foundation test asserts).
 *
 * - 0x01 subject erasure/restriction
 * - 0x02 PDA shred finalized
 * - 0x03 partner policy withdrawal
 * - 0x04 verifier/circuit deprecation
 * - 0x05 TEE integrity incident
 * - 0x06 claim generated under wrong PDA/config
 */
export const SD_REVOCATION_REASON = {
  SUBJECT_ERASURE_OR_RESTRICTION: 0x01,
  PDA_SHRED_FINALIZED: 0x02,
  PARTNER_POLICY_WITHDRAWAL: 0x03,
  VERIFIER_OR_CIRCUIT_DEPRECATION: 0x04,
  TEE_INTEGRITY_INCIDENT: 0x05,
  CLAIM_UNDER_WRONG_PDA_OR_CONFIG: 0x06,
} as const;

export type SdRevocationReasonCode = typeof SD_REVOCATION_REASON[keyof typeof SD_REVOCATION_REASON];

/** 6-entry list — Phase A foundation test asserts. */
export const SD_REVOCATION_REASON_COUNT = 6 as const;

/**
 * Solidity-side comment block for surgical-edit / dispatch site documentation.
 *
 * NO new on-chain Solidity constants — M2 already ships raw uint8 enum on
 * `revokeDisclosure(disclosureId, uint8 reasonCode, bytes32 evidenceRef)`.
 * Phase D's TS-side bridge embeds this comment at every call site.
 */
export const SD_REVOCATION_REASON_DOC_BLOCK = `// SD revocation reason codes (uint8) — §11.5 lines 1099-1106:
//   0x01 subject_erasure_or_restriction
//   0x02 pda_shred_finalized
//   0x03 partner_policy_withdrawal
//   0x04 verifier_or_circuit_deprecation
//   0x05 tee_integrity_incident
//   0x06 claim_under_wrong_pda_or_config`;
