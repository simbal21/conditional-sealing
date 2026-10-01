// S2-1 §4 — 22-field commit_AAD canonical layout.
//
// IMPORTANT: commit_AAD is NOT constructed by the configurator at PDA
// emission time. It is constructed at commit-create time by the M5
// (REST API) / M8 (Internal E2E Demo) commit pipeline. The configurator
// only references commit_AAD shape for:
//   - validation cross-checks (CI-14 — `commit_AAD` uses S2-1 §4 22-field structure);
//   - partner-readable inspection that surfaces commit-time fields (e.g., g3_choice, phase);
//   - audit-trail digest fields when a commit is recorded against this PDA.
//
// This type is a verbatim mirror of M1's `CommitAADInput` (snake_case keys
// matching `@cealis/v3-crypto` `src/codecs/commit-aad.ts`). Drift guard:
// foundation test `tests/foundation/m1-import-smoke.test.ts` round-trips
// the M1 encoder; CI-14 implementation in Phase B asserts shape parity.

import type { Bytes32 } from "../m1-imports.js";

/**
 * 22-field commit_AAD interface mirroring S2-1 §4 byte-exact layout.
 *
 * Field names use snake_case where the S2-1 spec uses snake_case, and
 * camelCase where the spec uses camelCase (`authorizationId`, `sdMerkleRoot`).
 * The names match `@cealis/v3-crypto`'s `CommitAADInput` interface exactly.
 */
export interface CommitAAD {
  readonly authorizationId: Bytes32;
  readonly pda_root: Bytes32;
  readonly schema_digest: Bytes32;
  readonly partner_id: Bytes32;
  /**
   * `commit_version` — per S2-1 §3.4 + S2-4 §2.2: `0x0302` for new
   * V2/V3-custody commits (A1+Shamir lifecycle).
   */
  readonly commit_version: number;
  readonly subject_commitment_v3: Bytes32;
  readonly sigma_subject_digest: Bytes32;
  readonly recipients_root: Bytes32;
  readonly p15_attestations_root: Bytes32;
  readonly endpoint_attestation_digest: Bytes32;
  readonly conditional_recipients_policy_digest: Bytes32;
  /**
   * `sdMerkleRoot` — per S2-1 §4 + S2-7 §12 + CI-10 / CI-14 / CI-20:
   *   - non-zero iff SD is enabled for this commit;
   *   - SD failures never block escrow (CI-08).
   */
  readonly sdMerkleRoot: Bytes32;
  /** G3 choice: 0x01 dcipher | 0x02 drand (per row 41 / CI-04 fixed-gate set). */
  readonly g3_choice: number;
  /** G4 phase: 0x01 Phase 1 | 0x02 Phase 2 (per row 42/43 + CI-15 + CF-05). */
  readonly phase: number;
  readonly composite_identity_type: number;
  readonly conditional_recipients_stanza_count: number;
  readonly plugin_version_digest: Bytes32;
  readonly g4_authority_ref: Bytes32;
  readonly dsl_version_ref: Bytes32;
  readonly oracle_references_root: Bytes32;
  readonly superseded_commit_ref: Bytes32;
  readonly commit_generation: number;
}

/** Canonical commit_AAD field-name list in S2-1 §4 order. */
export const COMMIT_AAD_FIELD_NAMES: readonly (keyof CommitAAD)[] = [
  "authorizationId",
  "pda_root",
  "schema_digest",
  "partner_id",
  "commit_version",
  "subject_commitment_v3",
  "sigma_subject_digest",
  "recipients_root",
  "p15_attestations_root",
  "endpoint_attestation_digest",
  "conditional_recipients_policy_digest",
  "sdMerkleRoot",
  "g3_choice",
  "phase",
  "composite_identity_type",
  "conditional_recipients_stanza_count",
  "plugin_version_digest",
  "g4_authority_ref",
  "dsl_version_ref",
  "oracle_references_root",
  "superseded_commit_ref",
  "commit_generation",
] as const;

/** Cross-spec invariant: 22 fields exactly per S2-1 §4. */
export const COMMIT_AAD_FIELD_COUNT = 22 as const;
