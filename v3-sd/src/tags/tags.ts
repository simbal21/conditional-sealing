// TAG_SD_*_V3 catalog — 12 entries verbatim from S2-7 §3.2 (lines 340–351).
//
// LOCK status: TAG count = 12, NOT 13. `TAG_SD_REVOCATION_V3` is RETIRED in
// Phase 2b per §3.4 line 410 (H-1 collapse). `disclosure_id` (§D.6 line 1818)
// is the unified Claim-proof policy handle keyed under `TAG_SD_COMMIT_V3`.
//
// Construction discipline (§3.1 lines 326-334): every SD tag is a 32-byte
// keccak-256 digest:
//
//   TAG_SD_NAME_V3 = keccak256(bytes("CEALIS_SD_NAME_V3"))
//
// The label string is ASCII, no NUL terminator, no trailing newline. Production
// code uses the precomputed `bytes32` value at construction sites. Raw label
// strings at construction sites are forbidden except in tag-table self-tests.
//
// S2-7 uses `CEALIS_SD_` labels to stay disjoint from S2-1 `CEALIS_V3_` labels.
// A collision in label, digest, or construction purpose between SD and escrow
// namespaces is a specification defect.

import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils.js";

/** SD label string set, verbatim from §3.2 lines 340–351. Used by tag self-tests. */
export const SD_TAG_LABELS = {
  TAG_SD_COMMIT_V3: "CEALIS_SD_COMMIT_V3",
  TAG_SD_FIELD_ID_V3: "CEALIS_SD_FIELD_ID_V3",
  TAG_SD_FIELD_V3: "CEALIS_SD_FIELD_V3",
  TAG_SD_PROOF_V3: "CEALIS_SD_PROOF_V3",
  TAG_SD_MERKLE_V3: "CEALIS_SD_MERKLE_V3",
  TAG_SD_SALT_V3: "CEALIS_SD_SALT_V3",
  TAG_SD_NULLIFIER_V3: "CEALIS_SD_NULLIFIER_V3",
  TAG_SD_CLAIM_V3: "CEALIS_SD_CLAIM_V3",
  TAG_SD_CLEARFIELD_V3: "CEALIS_SD_CLEARFIELD_V3",
  TAG_SD_VERIFIER_V3: "CEALIS_SD_VERIFIER_V3",
  TAG_SD_PLAN_V3: "CEALIS_SD_PLAN_V3",
  TAG_SD_SALT_CONTEXT_V3: "CEALIS_SD_SALT_CONTEXT_V3",
} as const;

export type SdTagName = keyof typeof SD_TAG_LABELS;

function k256(label: string): Uint8Array {
  return keccak_256(utf8ToBytes(label));
}

/** 12-entry TAG_SD_*_V3 byte32 catalog. Frozen at module load. */
export const TAG_SD = Object.freeze({
  TAG_SD_COMMIT_V3: k256(SD_TAG_LABELS.TAG_SD_COMMIT_V3),
  TAG_SD_FIELD_ID_V3: k256(SD_TAG_LABELS.TAG_SD_FIELD_ID_V3),
  TAG_SD_FIELD_V3: k256(SD_TAG_LABELS.TAG_SD_FIELD_V3),
  TAG_SD_PROOF_V3: k256(SD_TAG_LABELS.TAG_SD_PROOF_V3),
  TAG_SD_MERKLE_V3: k256(SD_TAG_LABELS.TAG_SD_MERKLE_V3),
  TAG_SD_SALT_V3: k256(SD_TAG_LABELS.TAG_SD_SALT_V3),
  TAG_SD_NULLIFIER_V3: k256(SD_TAG_LABELS.TAG_SD_NULLIFIER_V3),
  TAG_SD_CLAIM_V3: k256(SD_TAG_LABELS.TAG_SD_CLAIM_V3),
  TAG_SD_CLEARFIELD_V3: k256(SD_TAG_LABELS.TAG_SD_CLEARFIELD_V3),
  TAG_SD_VERIFIER_V3: k256(SD_TAG_LABELS.TAG_SD_VERIFIER_V3),
  TAG_SD_PLAN_V3: k256(SD_TAG_LABELS.TAG_SD_PLAN_V3),
  TAG_SD_SALT_CONTEXT_V3: k256(SD_TAG_LABELS.TAG_SD_SALT_CONTEXT_V3),
}) satisfies Record<SdTagName, Uint8Array>;

/** Expected count = 12. NOT 13. Guarded by foundation test. */
export const TAG_SD_COUNT = 12 as const;

/** Hex-encoded TAG_SD entries (no 0x prefix). Useful for log lines + tests. */
export const TAG_SD_HEX: Readonly<Record<SdTagName, string>> = Object.freeze(
  Object.fromEntries(
    (Object.keys(TAG_SD) as SdTagName[]).map((k) => [k, bytesToHex(TAG_SD[k])]),
  ) as Record<SdTagName, string>,
);

/**
 * RETIRED tag list — Phase A LOCKS this as the negative catalog. Foundation
 * test asserts NONE of these appear as `TAG_SD` keys.
 *
 * `TAG_SD_REVOCATION_V3` was retired in Phase 2b H-1 (S2-7 §3.4 line 410).
 * S2-1 may carry stale aliases (`TAG_SD_FIELD_COMMITMENT_V3`,
 * `TAG_SD_MERKLE_LEAF_V3`, `TAG_SD_BUNDLE_V3`) — never reintroduce.
 */
export const RETIRED_SD_TAGS = Object.freeze([
  "TAG_SD_REVOCATION_V3",
  "TAG_SD_FIELD_COMMITMENT_V3",
  "TAG_SD_MERKLE_LEAF_V3",
  "TAG_SD_BUNDLE_V3",
] as const);
