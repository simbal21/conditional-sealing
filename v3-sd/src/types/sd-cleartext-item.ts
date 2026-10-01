// App. I.5 `SdCleartextItem` — cleartext field item inside SdBundle.
// Verbatim from §App.I lines 2274-2288.
//
// LOCKED LITERAL: `policy_code === 1` (cleartext). NOT configurable.
//
// SdCleartextItem intentionally has NO `expiry_timestamp` or `disclosure_id`
// (§I.5 line 2293) — cleartext delivery is not SD-revocable.

import type { SdMerklePathElement } from "./sd-merkle-path.js";
import type { SdProof } from "./sd-proof.js";
import type { Hex, Hex32, HexScalar } from "./sd-bundle.js";

export const CLEARTEXT_POLICY_CODE = 1 as const;

export type CleartextOpeningModeLabel = "cleartext_zk_opened" | "cleartext_attested";

/**
 *   type SdCleartextItem = {
 *     field_id: Hex32;
 *     field_path_hash: Hex32;
 *     field_path_label?: string;
 *     field_type_code: number;
 *     value_encoding: string;
 *     value: unknown;
 *     field_commitment: HexScalar;
 *     policy_code: 1;
 *     merkle_path: SdMerklePathElement[];
 *     opening_mode: "cleartext_zk_opened" | "cleartext_attested";
 *     opening_proof?: SdProof;
 *     cleartext_attestation_digest?: Hex32;
 *   };
 */
export interface SdCleartextItem {
  readonly field_id: Hex32;
  readonly field_path_hash: Hex32;
  readonly field_path_label?: string;
  readonly field_type_code: number;
  readonly value_encoding: string;
  readonly value: unknown;
  readonly field_commitment: HexScalar;
  readonly policy_code: typeof CLEARTEXT_POLICY_CODE;
  readonly merkle_path: ReadonlyArray<SdMerklePathElement>;
  readonly opening_mode: CleartextOpeningModeLabel;
  readonly opening_proof?: SdProof;
  readonly cleartext_attestation_digest?: Hex32;
}

// Hex type re-exports for §App.I cross-module consumers.
export type { Hex, Hex32, HexScalar };
