// §5.4 BP-SD-1 binding — sdMerkleRoot at FIXED position in commit_AAD.
//
// VERBATIM §5.4 lines 534-555:
//
//   commit_AAD.sdMerkleRoot = sdMerkleRoot
//
//   "Current S2-1 CommitAAD includes sdMerkleRoot; S2-7 defines the SD-side
//   root and bundle digest that populate that field."
//
// BP-SD-1 status: CLOSED 2026-05-05 (S2-7 §17.3 line 1300). S2-1 CommitAAD
// has `sdMerkleRoot: [u8; 32]` at the FIXED offset documented in S2-1 §4.
// SD-disabled PDAs encode 32 zero bytes; SD-enabled PDAs that complete root
// construction encode non-zero scalar bytes.
//
// PHASE A LOCKED: M6 VERIFIES the binding correctness. S2-1 OWNS the offset.
// Phase E SD-BIND-001/002 tests in SDK validate match/mismatch behavior.
//
// Per §App.J line 2403, encoding is 32-byte big-endian scalar at the S2-1
// boundary. SD-enabled commits MUST be non-zero and equal to bundle root;
// SD-disabled commits MUST be 32 zero bytes; `sd_failed_before_root` (App.J
// §J.1) PDA is SD-enabled but encodes 32 zero bytes — escrow remains valid.

import type { Bytes32 } from "../tags/preimages.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { SdError } from "../errors/sd-error.js";
import { SdErrorCode } from "../errors/codes.js";

/**
 * 32-byte big-endian zero — the SD-disabled root + sd_failed_before_root
 * sentinel.
 */
export const SD_MERKLE_ROOT_ZERO: Bytes32 = new Uint8Array(32) as Bytes32;

export type SdBindingMode = "sd_disabled" | "sd_enabled" | "sd_failed_before_root";

/**
 * `verifySdRootBinding` — Phase B signature; Phase E SDK consumes.
 *
 * Inputs:
 *   - `bundle_root`: 32-byte scalar from `SdBundle.sdMerkleRoot` (decoded
 *      from `HexScalar`)
 *   - `commit_aad_root`: 32-byte scalar from S2-1 `commit_AAD.sdMerkleRoot`
 *   - `pda_sd_enabled`: whether PDA marks SD enabled
 *   - `bundle_status`: bundle `status` value ("complete" / "partial" / "failed" / "not_configured")
 *
 * Returns the detected `SdBindingMode` per §App.J §J.1 three-mode table.
 *
 * Phase B body throws `SdError` per §1.3 codes on mismatch.
 */
export interface VerifySdRootBindingInput {
  readonly bundle_root: Bytes32;
  readonly commit_aad_root: Bytes32;
  readonly pda_sd_enabled: boolean;
  readonly bundle_status: "complete" | "partial" | "failed" | "not_configured";
}

export interface VerifySdRootBinding {
  (input: VerifySdRootBindingInput): SdBindingMode;
}

export function verifySdRootBinding(input: VerifySdRootBindingInput): SdBindingMode {
  const bundleZero = isZero(input.bundle_root);
  const aadZero = isZero(input.commit_aad_root);

  if (!input.pda_sd_enabled) {
    if (!bundleZero || !aadZero || input.bundle_status !== "not_configured") {
      throw new SdError(SdErrorCode.ROOT_BINDING_MISSING, {
        stage: "partner_verify",
        safeRefs: { code: SdErrorCode.ROOT_BINDING_MISSING },
      });
    }
    return "sd_disabled";
  }

  if (input.bundle_status === "failed" && bundleZero && aadZero) return "sd_failed_before_root";

  if (bundleZero || aadZero || bytesToHex(input.bundle_root) !== bytesToHex(input.commit_aad_root)) {
    throw new SdError(SdErrorCode.ROOT_BINDING_MISSING, {
      stage: "partner_verify",
      safeRefs: { code: SdErrorCode.ROOT_BINDING_MISSING },
    });
  }
  return "sd_enabled";
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((b) => b === 0);
}
