// App. I.9 `SdProof` — proof object. Verbatim from §App.I lines 2343-2349.
//
// LOCKED literal: `proof_system === "plonk-bn254"`.
//
// SDK MUST verify `public_input_schema_digest` against verifier registry
// entry BEFORE calling proof verification (§I.9 line 2352). A proof generated
// under the right verifier but serialized with the wrong public-input schema
// MUST fail before cryptographic verification.

import type { Hex, Hex32 } from "./sd-bundle.js";

export const SD_PROOF_SYSTEM = "plonk-bn254" as const;

/**
 *   type SdProof = {
 *     proof_system: "plonk-bn254";
 *     verifier_ref: Hex32;
 *     proof: Hex;
 *     public_inputs: string[];                  // DECIMAL strings; see SdClaimItem
 *     public_input_schema_digest: Hex32;
 *   };
 */
export interface SdProof {
  readonly proof_system: typeof SD_PROOF_SYSTEM;
  readonly verifier_ref: Hex32;
  readonly proof: Hex;
  readonly public_inputs: ReadonlyArray<string>;
  readonly public_input_schema_digest: Hex32;
}
