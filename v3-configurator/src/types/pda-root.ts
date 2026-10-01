// S2-1 §3.3 — 29-field pda_root canonical layout (the cryptographic form).
// S2-2 App. A — Solidity `struct PdaRootFields` mirror.
// S2-4 §1.1 — canonical JSON is the human/audit form; S2-1 §3.3 is the
//             cryptographic form. This file defines the TypeScript interface
//             consumed by the configurator emit pipeline AND audit trail.
//
// Drift guard: this interface is verbatim cross-checked against M1's
// `PDARootInput` (`@cealis/v3-crypto` `src/codecs/pda-root.ts`) and M2's
// Solidity struct (`contracts/src/lib/Structs.sol`
// `struct PdaRootFields`). Foundation test
// `tests/foundation/m1-m2-differential.test.ts` asserts the 29-field count
// and field-name correspondence across all three layers.
//
// Per S2-1 §3.3.2 "conditional binding rule" (D1-normative): every field
// MUST appear in the preimage regardless of value; "not applicable"
// semantics use the zero-value of the field's type. This is enforced at
// hash time by M1.

import type { Bytes32 } from "../m1-imports.js";

/**
 * 29-field PdaRootFields interface mirroring S2-1 §3.3 byte-exact layout.
 *
 * Naming convention: snake_case for TypeScript-side fields. Solidity-side
 * (M2) uses lowerCamelCase. The two mappings are byte-equivalent because
 * the hash is computed from a 540-byte fixed-width preimage; field NAMES
 * are not part of the preimage, only field VALUES in fixed positions.
 *
 * Field order in this interface MUST match S2-1 §3.3.3 (16 original) +
 * §3.3.4 (13 D1 additions). Reordering is forbidden — it would silently
 * change the byte preimage and break pda_root reproducibility.
 */
export interface PdaRootFields {
  // §3.3.3 — original 16 fields ---------------------------------------------
  /** Stable PDA identifier (commit-bound, not partner-id). */
  readonly pda_id: Bytes32;
  /** PDA version number; new versions produce new pda_roots (§10.2). */
  readonly pda_version: bigint;
  /** Reveal condition mode: 0x01 = Mode F (FSM); 0x02 = Mode P (predicate). */
  readonly reveal_condition_mode: number;
  /** Reveal condition spec content-addressed digest. */
  readonly reveal_condition_spec_hash: Bytes32;
  /** Shred condition mode: 0x01 = Mode F (FSM); 0x02 = Mode P (predicate). */
  readonly shred_condition_mode: number;
  /** Shred condition spec content-addressed digest. */
  readonly shred_condition_spec_hash: Bytes32;
  /** Merkle/keccak root over selected oracle references (OracleRegistry). */
  readonly oracle_references_root: Bytes32;
  /** DSL version digest (DSLVersionRegistry entry ref). */
  readonly dsl_version: Bytes32;
  /** Merkle/keccak root over selected WASM predicate hashes (PluginHashRegistry). */
  readonly wasm_predicate_hashes_root: Bytes32;
  /** Merkle/keccak root over allowed submitter sets per oracle binding. */
  readonly submitter_sets_root: Bytes32;
  /** Pause authority id (Partner / Joint / None — per row 73 enum). */
  readonly pause_authority_id: Bytes32;
  /** Ceremony resolver id (human/judicial address for legal-effect PDAs). */
  readonly ceremony_resolver_id: Bytes32;
  /** Merkle/keccak root over reveal-axis eligible challenger roles + named observers. */
  readonly eligible_challengers_reveal_root: Bytes32;
  /** Merkle/keccak root over shred-axis eligible challenger roles + named observers. */
  readonly eligible_challengers_shred_root: Bytes32;
  /** Content-addressed FSM/condition template id. */
  readonly template_id: Bytes32;
  /** Partner identifier (commits across PDA versions). */
  readonly partner_id: Bytes32;

  // §3.3.4 — 13 D1 additions ------------------------------------------------
  /**
   * Subject authenticator class:
   *   - 0x01 platform authenticator (default web/mobile FIDO2)
   *   - 0x02 QTSP QES signing (§371a posture)
   *   - 0x03 synced passkey
   */
  readonly subject_authenticator_class: number;
  /** QTSP provider registry ref; zeroed when QES posture is not required. */
  readonly qtsp_provider_ref: Bytes32;
  /** Whether the PDA processes special-category personal data per Art. 9 GDPR. */
  readonly art_9_scoped: boolean;
  /** Selected Art. 9(2) basis taxonomy id; 0x00 when `art_9_scoped === false`. */
  readonly art_9_basis_id: number;
  /** Whether the PDA expects production of "legal effects" on the subject (Art. 22 trigger). */
  readonly legal_effect_expected: boolean;
  /** Cealis class-wide halt opt-out flag; CF-02 forbids true when legal_effect_expected. */
  readonly cealis_class_wide_halt_opt_out: boolean;
  /** Minimum shred latency in seconds (§5.2 row 27 floor / row 28 PDA value). */
  readonly minimum_shred_latency: bigint;
  /** Applicable jurisdiction (scalar code or merkle root over a set). */
  readonly applicable_jurisdiction: Bytes32;
  /** Whether conditional recipients are updatable post-commit (long-TTL guardrail). */
  readonly conditional_recipients_updatable: boolean;
  /** Whether subject liveness is required at firing (SUBJECT_SELF interlock — CF-04). */
  readonly subject_liveness_required_at_fire: boolean;
  /** Subject acknowledgment of long-TTL bricking risk when immutability selected. */
  readonly emergency_response_bricking_acknowledgment: boolean;
  /** Time-critical PDA flag (affirmative-harm deadline risk; forces updatability). */
  readonly time_critical_pda_flag: boolean;
  /** Whether the PDA itself is updatable (long-TTL default true per §13.2). */
  readonly pda_updatable: boolean;
}

/**
 * Canonical field-name list in S2-1 §3.3 order. Frozen for cross-spec
 * differential testing.
 */
export const PDA_ROOT_FIELD_NAMES: readonly (keyof PdaRootFields)[] = [
  // §3.3.3 — 16 original
  "pda_id",
  "pda_version",
  "reveal_condition_mode",
  "reveal_condition_spec_hash",
  "shred_condition_mode",
  "shred_condition_spec_hash",
  "oracle_references_root",
  "dsl_version",
  "wasm_predicate_hashes_root",
  "submitter_sets_root",
  "pause_authority_id",
  "ceremony_resolver_id",
  "eligible_challengers_reveal_root",
  "eligible_challengers_shred_root",
  "template_id",
  "partner_id",
  // §3.3.4 — 13 D1 additions
  "subject_authenticator_class",
  "qtsp_provider_ref",
  "art_9_scoped",
  "art_9_basis_id",
  "legal_effect_expected",
  "cealis_class_wide_halt_opt_out",
  "minimum_shred_latency",
  "applicable_jurisdiction",
  "conditional_recipients_updatable",
  "subject_liveness_required_at_fire",
  "emergency_response_bricking_acknowledgment",
  "time_critical_pda_flag",
  "pda_updatable",
] as const;

/** Cross-spec invariant: 29 fields exactly. */
export const PDA_ROOT_FIELD_COUNT = 29 as const;
