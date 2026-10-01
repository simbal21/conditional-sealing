// App. I.4 `SdBundle` — partner-facing onboarding response payload (semantic
// shape; S2-5 owns transport). Verbatim from §App.I lines 2245-2265.
//
// LOCKED literals (§I.4 + §8.1):
//   sd_version === "s2-7-1.0"  (immutable; foundation test asserts)
//   rootBindingLevel === "commit_AAD"  (only valid for active `0x0302`)
//
// Status enum (§I.4 line 2247 + §7.5):
//   complete / partial / failed / not_configured

import type { Bytes32 } from "../tags/preimages.js";
import type { SdClaimItem } from "./sd-claim-item.js";
import type { SdCleartextItem } from "./sd-cleartext-item.js";
import type { SdFailureItem } from "./sd-failure-item.js";

export const SD_BUNDLE_VERSION = "s2-7-1.0" as const;
export const ROOT_BINDING_LEVEL = "commit_AAD" as const;

export type SdBundleStatus = "complete" | "partial" | "failed" | "not_configured";

export type Hex = `0x${string}`;
export type Hex32 = `0x${string}`;
export type HexScalar = `0x${string}`;

/**
 * Partner-facing SD bundle. SDK consumes this shape verbatim. SDKs may carry
 * the same shape in browser, Node, Rust bindings via JSON.
 *
 *   type SdBundle = {
 *     sd_version: "s2-7-1.0";
 *     status: "complete" | "partial" | "failed" | "not_configured";
 *     authorizationId: Hex32;
 *     h_commit: Hex32;
 *     pda_root: Hex32;
 *     partner_id: Hex32;
 *     pda_id: Hex32;
 *     pda_version: string;
 *     schema_digest: Hex32;
 *     sdMerkleRoot?: HexScalar;
 *     sd_salt_context_digest: Hex32;
 *     sd_plan_digest: Hex32;
 *     sd_bundle_digest: Hex32;
 *     rootBindingLevel: "commit_AAD";
 *     generated_at: string;
 *     tee_attestation_ref?: Hex32;
 *     cleartext: SdCleartextItem[];
 *     claims: SdClaimItem[];
 *     failures: SdFailureItem[];
 *   };
 */
export interface SdBundle {
  readonly sd_version: typeof SD_BUNDLE_VERSION;
  readonly status: SdBundleStatus;
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly pda_root: Hex32;
  readonly partner_id: Hex32;
  readonly pda_id: Hex32;
  readonly pda_version: string;
  readonly schema_digest: Hex32;
  readonly sdMerkleRoot?: HexScalar;
  readonly sd_salt_context_digest: Hex32;
  readonly sd_plan_digest: Hex32;
  readonly sd_bundle_digest: Hex32;
  readonly rootBindingLevel: typeof ROOT_BINDING_LEVEL;
  readonly generated_at: string;
  readonly tee_attestation_ref?: Hex32;
  readonly cleartext: ReadonlyArray<SdCleartextItem>;
  readonly claims: ReadonlyArray<SdClaimItem>;
  readonly failures: ReadonlyArray<SdFailureItem>;
}

// Bytes32 (raw byte form) re-exported for non-JSON consumers.
export type { Bytes32 };
