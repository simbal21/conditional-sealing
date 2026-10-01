// App. I.1 `SdPlan` — compiled disclosure plan emitted by the configurator
// and re-derived by ingestion. Verbatim from §App.I lines 2174-2188.
//
// LOCKED literal: `sd_version === 0x0001` for S2-7 initial release.

import type { Bytes32 } from "../tags/preimages.js";

export const SD_PLAN_VERSION = 0x0001 as const;

/**
 * SCALE-shaped TS type. SCALE encoding details live in Phase B `sd-plan/`.
 *
 *   struct SdPlan {
 *     sd_version:                         u16,       // 0x0001 for S2-7 initial release
 *     partner_id:                         [u8; 32],
 *     pda_id:                             [u8; 32],
 *     pda_version:                        u64,
 *     schema_digest:                      [u8; 32],
 *     ingestion_mode:                     u8,        // must be 0x01 Mode A when sd_enabled = true
 *     sd_enabled:                         bool,
 *     field_policy_root:                  [u8; 32],
 *     claim_plan_root:                    [u8; 32],
 *     default_expiry_policy_ref:          [u8; 32],
 *     revocation_policy_ref:              [u8; 32],
 *     cleartext_attestation_allowed:      bool,
 *     public_composability_allowed:       bool
 *   }
 */
export interface SdPlan {
  readonly sd_version: typeof SD_PLAN_VERSION;
  readonly partner_id: Bytes32;
  readonly pda_id: Bytes32;
  readonly pda_version: bigint;
  readonly schema_digest: Bytes32;
  /** 0x01 = MODE_A; only valid value when `sd_enabled = true`. */
  readonly ingestion_mode: number;
  readonly sd_enabled: boolean;
  readonly field_policy_root: Bytes32;
  readonly claim_plan_root: Bytes32;
  readonly default_expiry_policy_ref: Bytes32;
  readonly revocation_policy_ref: Bytes32;
  /**
   * If `false`, every cleartext field MUST carry a ZK equality opening
   * (§I.1 line 2193 + §4.4).
   */
  readonly cleartext_attestation_allowed: boolean;
  /**
   * Required `true` before any Claim proof may be on-chain-registered with
   * public inputs (§I.1 line 2194).
   */
  readonly public_composability_allowed: boolean;
}

export const MODE_A_INGESTION_MODE_CODE = 0x01 as const;
export const MODE_B_INGESTION_MODE_CODE = 0x02 as const;
