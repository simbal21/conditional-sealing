// App. I.7 `SdFailureItem` — failure item inside SdBundle. Verbatim from
// §App.I lines 2316-2324.
//
// `detail_ref` is a digest or encrypted diagnostic ref. It MUST NEVER be raw
// plaintext, raw witness, raw salt, raw proof transcript, or stack trace
// containing PII (§I.7 line 2327).

import type { Hex32 } from "./sd-bundle.js";
import type { SdErrorCodeValue } from "../errors/codes.js";

export type SdFailureScope =
  | "bundle"
  | "field"
  | "claim"
  | "registry"
  | "mode"
  | "prover"
  | "verifier";

/**
 *   type SdFailureItem = {
 *     scope: "bundle" | "field" | "claim" | "registry" | "mode" | "prover" | "verifier";
 *     field_id?: Hex32;
 *     claim_id?: Hex32;
 *     error: SdErrorCode;
 *     retryable: boolean;
 *     detail_ref?: Hex32;
 *   };
 */
export interface SdFailureItem {
  readonly scope: SdFailureScope;
  readonly field_id?: Hex32;
  readonly claim_id?: Hex32;
  readonly error: SdErrorCodeValue;
  readonly retryable: boolean;
  readonly detail_ref?: Hex32;
}
