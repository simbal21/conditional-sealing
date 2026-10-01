// App. I.6 `SdClaimItem` — Claim proof item inside SdBundle. Verbatim from
// §App.I lines 2297-2310.
//
// LOCKED rules (§I.6 line 2312):
//   - `public_inputs[*]` MUST be DECIMAL STRING (regex `^[0-9]+$`).
//     NOT JSON number — avoids JavaScript number precision loss on BN254
//     scalar values.
//   - `disclosure_id` is a Claim-proof policy handle, NOT a field-commitment
//     or cleartext-output handle.

import type { Hex, Hex32 } from "./sd-bundle.js";
import type { ClaimTypeLabel } from "./predicates.js";

export type { ClaimTypeLabel };

/**
 *   type SdClaimItem = {
 *     claim_id: Hex32;
 *     claim_type: "range" | "equality" | "set_membership" | "non_equality" | "composed";
 *     field_ids: Hex32[];
 *     verifier_ref: Hex32;
 *     proof: Hex;
 *     public_inputs: string[];           // DECIMAL strings, regex ^[0-9]+$
 *     proof_context_digest: Hex32;
 *     expiry_timestamp: number;
 *     disclosure_id: Hex32;
 *     on_chain_registered: boolean;
 *   };
 */
export interface SdClaimItem {
  readonly claim_id: Hex32;
  readonly claim_type: ClaimTypeLabel;
  readonly field_ids: ReadonlyArray<Hex32>;
  readonly verifier_ref: Hex32;
  readonly proof: Hex;
  /** Decimal-string array. Regex `^[0-9]+$` enforced by foundation test. */
  readonly public_inputs: ReadonlyArray<string>;
  readonly proof_context_digest: Hex32;
  readonly expiry_timestamp: number;
  readonly disclosure_id: Hex32;
  readonly on_chain_registered: boolean;
}

export const PUBLIC_INPUTS_DECIMAL_REGEX = /^[0-9]+$/;
