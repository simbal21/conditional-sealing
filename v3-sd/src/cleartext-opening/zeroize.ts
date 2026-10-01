// Caller-side cleartext zeroization helper.
//
// Per S2-7 SD-D1/D3: SD cleartext fields are delivered at onboarding time and
// the SD pipeline destroys its internal salt + plaintext-buffer state after
// TEE processing (see `v3-sd/src/sd-plan/finalizer.ts`).
//
// HOWEVER: the returned `bundle.cleartext: SdCleartextItem[]` carries the
// partner-visible field values, and lives in the caller's heap until garbage
// collection. Security-audit-2026-05-14 TS-API-F-07 flagged this as a partial
// SD-D1/D3 compliance gap — the partner SDK should provide an explicit
// zeroization helper that the partner invokes after consuming the cleartext.
//
// This module exposes such a helper. It best-effort zeroes:
//   - Uint8Array `.value` fields (the canonical encoding for binary blobs)
//   - String `.value` fields are JavaScript-immutable; we overwrite the
//     reference with the empty string and instruct callers that any local
//     copies they made remain their responsibility.
//   - Numeric `.value` fields are JS-immutable primitives; we replace with 0.
//   - `merkle_path` arrays are emptied.
//
// JavaScript's runtime does NOT guarantee key/buffer eviction after Uint8Array
// `.fill(0)`. The helper closes the OBVIOUS heap-residue surface but does not
// substitute for executing the post-onboarding consumption flow inside a
// memory-isolated environment (TEE / WASM sandbox / separate process).

import type { SdCleartextItem } from "../types/sd-cleartext-item.js";

/**
 * Mutates an `SdCleartextItem` array in place, best-effort zeroing every
 * field-value buffer + merkle path. Returns the count of items processed.
 *
 * IMPORTANT: this helper MUTATES `readonly` types. TypeScript hides the
 * mutability of the underlying objects; runtime mutation works. Callers
 * passing frozen objects will get a no-op without error (defensive).
 *
 * Security-audit-2026-05-14 TS-API-F-07.
 */
export function zeroizeSdCleartext(items: ReadonlyArray<SdCleartextItem>): number {
  let processed = 0;
  for (const item of items) {
    const m = item as unknown as Record<string, unknown>;
    try {
      const value = m.value;
      if (value instanceof Uint8Array) {
        value.fill(0);
      } else if (typeof value === "string") {
        m.value = "";
      } else if (typeof value === "number") {
        m.value = 0;
      } else if (typeof value === "object" && value !== null) {
        // Best-effort: walk one level and zero any nested Uint8Array.
        for (const k of Object.keys(value as Record<string, unknown>)) {
          const v = (value as Record<string, unknown>)[k];
          if (v instanceof Uint8Array) v.fill(0);
        }
      }
      // Empty merkle_path — references to inner objects survive but the path
      // array itself loses its length.
      if (Array.isArray(m.merkle_path)) {
        (m.merkle_path as unknown[]).length = 0;
      }
      // Drop opening_proof if present (carries SD witness material).
      if (m.opening_proof !== undefined) {
        m.opening_proof = undefined;
      }
      processed++;
    } catch {
      // Frozen object → silent skip (caller chose immutability over zeroization).
    }
  }
  return processed;
}

/**
 * Convenience wrapper for an `SdBundle.cleartext` field. Returns the count
 * of items zeroed.
 */
export function zeroizeSdBundleCleartext(bundle: { cleartext?: ReadonlyArray<SdCleartextItem> }): number {
  if (bundle.cleartext === undefined) return 0;
  return zeroizeSdCleartext(bundle.cleartext);
}
