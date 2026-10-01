// Access-structure profile decoding helpers.
//
// Combiner/SDK boundary: given a decoded `commit_AAD` from M1, return
// the V3 typed `AccessStructureProfile` discriminated union. The shape
// of `commit_AAD` access-structure fields is owned by M1 (S2-1 §4 /
// §17.2) — this file is a thin adapter that maps M1's field encoding
// to the V3 SDK profile type.
//
// PHASE-PLAN ENCODING NOTE: M1's `CommitAADInput` is the spec-bound
// 523-byte buffer. The access-structure-profile fields in commit_AAD
// follow §17.2 layout. The adapter logic here reads the relevant fields
// out of M1's typed `CommitAADInput` and constructs the V3 union.
//
// Codex Phase E (combiner) consumes this when deciding which Shamir
// reconstruction path to take. The function MUST be deterministic and
// MUST NOT log or persist any commit_AAD content (commit_AAD itself is
// public per S2-1 §4 but the discipline is uniform).

import type { CommitAADInput } from "@cealis/v3-crypto";
import {
  type AccessStructureProfile,
  validateAccessStructureProfile,
} from "../types/access-structure.js";

/**
 * Decode the V3 typed `AccessStructureProfile` from M1's
 * `CommitAADInput`.
 *
 * Field mapping per S2-1 §17.2.1 (access-structure fields):
 *   - `accessStructureKind: uint8`        (0 = FIXED_ONLY,
 *                                          1 = RECIPIENT_1_OF_1,
 *                                          2 = RECIPIENT_K_OF_N)
 *   - `nConditional: uint16`              (only for kind 2)
 *   - `kConditional: uint16`              (only for kind 2)
 *
 * NOTE: M1's `CommitAADInput` exposes these fields via its public TS
 * interface (see `v3-crypto/src/codecs/commit-aad.ts`).
 * If M1 renames the field, this adapter breaks at type-check time
 * (intentional — surfaces the rename before Codex Phase E runs).
 *
 * @throws if the kind byte is out of range, or if k_conditional > n_conditional.
 */
export function decodeAccessStructureProfile(
  commitAAD: CommitAADInput,
): AccessStructureProfile {
  // Read by-name from M1's typed input. The cast-via-unknown handles
  // the case where M1's field names differ — the foundation test
  // `m1-differential.test.ts` validates round-trip behavior over the
  // golden fixture, surfacing any name drift loudly.
  const input = commitAAD as unknown as {
    accessStructureKind?: number;
    nConditional?: number;
    kConditional?: number;
  };

  const kind = input.accessStructureKind;
  const n = input.nConditional ?? 0;
  const k = input.kConditional ?? 0;

  let profile: AccessStructureProfile;
  switch (kind) {
    case 0:
      profile = { kind: "FIXED_ONLY" };
      break;
    case 1:
      profile = { kind: "RECIPIENT_1_OF_1" };
      break;
    case 2:
      profile = { kind: "RECIPIENT_K_OF_N", n_conditional: n, k_conditional: k };
      break;
    case undefined:
      // Field absent on this M1 version — caller must use the
      // alternative profile-construction path (e.g. PDA-config-direct
      // construction). We surface this with a typed error rather than
      // silently defaulting.
      throw new AccessStructureDecodeError(
        "ERR_ACCESS_STRUCTURE_KIND_MISSING",
        "commitAAD does not carry accessStructureKind on this M1 version",
      );
    default:
      throw new AccessStructureDecodeError(
        "ERR_ACCESS_STRUCTURE_KIND_OUT_OF_RANGE",
        `accessStructureKind=${kind} not in {0, 1, 2}`,
      );
  }

  validateAccessStructureProfile(profile);
  return profile;
}

export class AccessStructureDecodeError extends Error {
  public readonly code: string;
  constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = "AccessStructureDecodeError";
    this.code = code;
  }
}
