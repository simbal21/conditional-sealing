// Mode B + SD module-level rejection guard per §14 (NORMATIVE).
//
// §14.2 line 1187 VERBATIM:
//   "Mode B with `sd_enabled = false` is valid and returns a disabled SD plan.
//   The incompatibility is Mode B plus this TEE-side SD pipeline, not Mode B
//   as an escrow mode."
//
// §14.2 line 1182 VERBATIM:
//   ingestion_mode = MODE_B && sd_enabled = true → ERR_SD_CONFIG_MODE_B_INCOMPATIBLE
//
// Phase A LOCKED — defense-in-depth check that fires at both configurator
// time (S2-4) AND API request time (S2-5). M6 owns the SD-side
// `assertModeBSdCompatible` and a foundation test covering BOTH branches.

import { sdErrors } from "../errors/sd-error.js";
import { MODE_A_INGESTION_MODE_CODE, MODE_B_INGESTION_MODE_CODE } from "../types/sd-plan.js";

export type IngestionMode = "MODE_A" | "MODE_B";

export interface AssertModeBSdCompatibleInput {
  readonly ingestion_mode: IngestionMode;
  readonly sd_enabled: boolean;
  readonly correlationId?: string;
}

/**
 * `assertModeBSdCompatible` — accepts both branches and ONLY throws on the
 * forbidden combination.
 *
 * Branch 1 (ACCEPT — silent return): MODE_B + sd_enabled=false → no error.
 *   The SD plan is disabled; ingestion proceeds without SD execution.
 *
 * Branch 2 (REJECT — throw): MODE_B + sd_enabled=true →
 *   `ERR_SD_CONFIG_MODE_B_INCOMPATIBLE` via `sdErrors.configModeBIncompatible`.
 *   `safeRefs` carries `correlationId` only — no plaintext, no proof bytes,
 *   no SD plan contents.
 *
 * Branch 3 (ACCEPT — silent return): MODE_A + sd_enabled=true → no error.
 *   The SD plan is enabled and ingestion proceeds with SD execution.
 *
 * Branch 4 (ACCEPT — silent return): MODE_A + sd_enabled=false → no error.
 *   Standard escrow-only commit, no SD.
 *
 * Phase A foundation test covers both branches 1 (ACCEPT) and 2 (REJECT) per
 * PHASE-PLAN §0 item #4.
 */
export function assertModeBSdCompatible(input: AssertModeBSdCompatibleInput): void {
  if (input.ingestion_mode === "MODE_B" && input.sd_enabled === true) {
    const opts: { correlationId?: string } = {};
    if (input.correlationId !== undefined) {
      opts.correlationId = input.correlationId;
    }
    sdErrors.configModeBIncompatible(opts);
  }
  // MODE_B + sd_enabled=false   → silent accept (§14.2 line 1187)
  // MODE_A + sd_enabled=true    → silent accept
  // MODE_A + sd_enabled=false   → silent accept
}

/** Numeric ingestion-mode code map — Phase B uses for SCALE encoding consistency. */
export const INGESTION_MODE_CODE_MAP: Readonly<Record<IngestionMode, number>> = Object.freeze({
  MODE_A: MODE_A_INGESTION_MODE_CODE,
  MODE_B: MODE_B_INGESTION_MODE_CODE,
});

export function ingestionModeFromCode(code: number): IngestionMode {
  if (code === MODE_A_INGESTION_MODE_CODE) return "MODE_A";
  if (code === MODE_B_INGESTION_MODE_CODE) return "MODE_B";
  throw new RangeError(`unknown ingestion mode code: ${code}`);
}
