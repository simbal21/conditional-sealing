// App. I.2 `SdFieldPolicy` — per-field policy carried inside SD plan. Verbatim
// from §App.I lines 2198-2211.

import type { Bytes32 } from "../tags/preimages.js";

/**
 * Per-field SD policy (SCALE-shaped). Phase B Merkle library builds the
 * `field_policy_root` over an ordered list of these records.
 *
 *   struct SdFieldPolicy {
 *     field_index:                        u32,
 *     field_id:                           [u8; 32],
 *     field_path_hash:                    [u8; 32],
 *     field_type_code:                    u8,
 *     policy:                             u8,        // 1 cleartext, 2 zkp, 3 escrow_only
 *     nullable:                           bool,
 *     max_byte_length:                    u32,
 *     numeric_bit_width:                  u16,
 *     decimal_scale:                      u8,
 *     allowed_claim_ids_root:             [u8; 32],
 *     cleartext_opening_mode:             u8,        // 0 none, 1 zk_opened, 2 tee_attested
 *     pii_class:                          u8         // 0 none, 1 ordinary, 2 special_category, 3 financial, 4 legal
 *   }
 */
export interface SdFieldPolicy {
  readonly field_index: number;
  readonly field_id: Bytes32;
  readonly field_path_hash: Bytes32;
  readonly field_type_code: number;
  readonly policy: SdFieldPolicyCode;
  readonly nullable: boolean;
  readonly max_byte_length: number;
  readonly numeric_bit_width: number;
  readonly decimal_scale: number;
  readonly allowed_claim_ids_root: Bytes32;
  readonly cleartext_opening_mode: CleartextOpeningModeCode;
  readonly pii_class: PiiClassCode;
}

export const SD_FIELD_POLICY_CODE = {
  CLEARTEXT: 1,
  ZKP: 2,
  ESCROW_ONLY: 3,
} as const;

export type SdFieldPolicyCode = typeof SD_FIELD_POLICY_CODE[keyof typeof SD_FIELD_POLICY_CODE];

/**
 * §App.I line 2209: `cleartext_opening_mode: u8` — 0 none, 1 zk_opened
 * (DEFAULT), 2 tee_attested. Mirror constant exported from
 * `src/types/cleartext-opening.ts` for cross-module type safety.
 */
export const CLEARTEXT_OPENING_MODE = {
  NONE: 0,
  ZK_OPENED: 1,
  TEE_ATTESTED: 2,
} as const;

export type CleartextOpeningModeCode = typeof CLEARTEXT_OPENING_MODE[keyof typeof CLEARTEXT_OPENING_MODE];

export const PII_CLASS = {
  NONE: 0,
  ORDINARY: 1,
  SPECIAL_CATEGORY: 2,
  FINANCIAL: 3,
  LEGAL: 4,
} as const;

export type PiiClassCode = typeof PII_CLASS[keyof typeof PII_CLASS];
