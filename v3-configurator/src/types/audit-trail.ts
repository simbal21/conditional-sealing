// S2-4 §1.4 — Configurator audit trail (append-only, PII-excluded).
//
// "The configurator audit trail is append-only. It records:
//   - input form digest;
//   - translated PDA JSON digest;
//   - template ids and version refs;
//   - validation result set;
//   - simulation result digest;
//   - human reviewer identity digest;
//   - emitted `pda_root`;
//   - IPFS CIDs;
//   - on-chain transaction refs."
//
// "It does not log plaintext subject data, raw attestation payloads, raw
// recipient secrets, σ values, Shamir shares, DEK, SD salts, plaintext
// refusal reasons for sensitive G4 codes, or delivery URL bodies. When
// a recipient binding must be identified in logs, use row id plus hash
// digest."
//
// Phase A locks the record shape with `readonly` modifiers + a redact()
// helper signature. Phase E's emit pipeline writes records exclusively
// through this typed surface; Phase E's `redaction/log-sanitize.ts`
// extends with run-time grep for PII patterns.
//
// SPEC-COMPLIANCE-GUARD §9 + §23:
//   - audit-trail surface MUST NOT log σ;
//   - inspection surface MUST NOT log σ;
//   - JSON.stringify(record) MUST NOT emit Shamir share / DEK / salt /
//     raw-KYC / plaintext-refusal-reason bytes.

import type { Bytes32 } from "../m1-imports.js";

/**
 * One append-only audit trail record per configurator emission.
 *
 * The spec lists 9 record fields. Phase A reads "validation result set"
 * as an explicit field (`validation_result_set`), giving the brief's
 * 10-field formulation. Where the spec says "human reviewer identity
 * digest" the field is a digest, not the identity itself.
 *
 * All fields are `readonly` to enforce append-only at the type level.
 */
export interface AuditTrailRecord {
  /** Spec field 1: input form digest. */
  readonly input_form_digest: Bytes32;
  /** Spec field 2: translated PDA JSON digest. */
  readonly translated_pda_json_digest: Bytes32;
  /** Spec field 3: template ids and version refs. */
  readonly template_ids: ReadonlyArray<Bytes32>;
  /**
   * Spec field 4: validation result set.
   *
   * Represented as an opaque digest + count summary. Phase E writes
   * the full structured result to a separate persistence layer; the
   * audit trail records only the digest + counts (and stage tally).
   */
  readonly validation_result_set: {
    readonly digest: Bytes32;
    readonly pass: boolean;
    readonly stage1_pass: boolean;
    readonly stage2_pass: boolean;
    readonly stage3_pass: boolean;
    readonly stage4_pass: boolean;
    readonly stage5_pass: boolean;
    readonly failure_count: number;
  };
  /** Spec field 5: simulation result digest. */
  readonly simulation_result_digest: Bytes32;
  /**
   * Spec field 6: human reviewer identity digest.
   *
   * NEVER the raw identity — a one-way digest the reviewer system can
   * verify against a known reviewer set. Phase E sources the digest
   * from the Cealis-internal review surface.
   */
  readonly human_reviewer_identity_digest: Bytes32;
  /** Spec field 7: emitted `pda_root`. */
  readonly emitted_pda_root: Bytes32;
  /** Spec field 8: IPFS CIDs. */
  readonly ipfs_cids: ReadonlyArray<string>;
  /** Spec field 9: on-chain transaction refs. */
  readonly on_chain_tx_refs: ReadonlyArray<{
    readonly chain_id: number;
    readonly tx_hash: Bytes32;
    readonly block_number: bigint;
  }>;
  /** Append-only timestamp (UTC epoch seconds at record write time). */
  readonly recorded_at_unix_seconds: bigint;
}

/**
 * Cross-spec invariant: 10 fields per §1.4 enumeration + recorded_at.
 * The "validation result set" counts as one logical record field per spec.
 */
export const AUDIT_TRAIL_FIELD_COUNT = 10 as const;

export const AUDIT_TRAIL_FIELD_NAMES: readonly (keyof AuditTrailRecord)[] = [
  "input_form_digest",
  "translated_pda_json_digest",
  "template_ids",
  "validation_result_set",
  "simulation_result_digest",
  "human_reviewer_identity_digest",
  "emitted_pda_root",
  "ipfs_cids",
  "on_chain_tx_refs",
  "recorded_at_unix_seconds",
] as const;

/**
 * PII patterns that MUST NEVER appear in audit-trail records or
 * partner-inspection rendering. Per §1.4 exclusion list. Phase E's
 * `redaction/log-sanitize.ts` greps these patterns at runtime; Phase F
 * adds a static `grep -rE "sigma|σ|shamir|DEK|kdf"
 *   v3-configurator/src/pda/audit-trail.ts
 *   v3-configurator/src/pda/inspection.ts` check that
 * returns zero.
 */
export const PII_EXCLUSION_PATTERNS: readonly string[] = [
  // σ-as-authorization doctrine — σ NEVER logged.
  "sigma_lit",
  "sigma_g3",
  "sigma_g4",
  "sigma_subject",
  // Shamir share material (per S2-1 §6 Shamir lifecycle).
  "shamir_share",
  "shamir_secret",
  // DEK + intermediate key material.
  "dek_raw",
  "dek_bytes",
  "hkdf_ikm",
  // SD salt material (per S2-7 §11 — ephemeral TEE-only).
  "sd_salt",
  // Raw KYC field values.
  "raw_kyc",
  "plaintext_pii",
  "subject_legal_name",
  "subject_id_document_number",
  // Plaintext G4 refusal reasons for sensitive codes (0x02 / 0x03 are
  // encrypted per S2-3 §6.5 + memory feedback_v3_sigma_is_key_material.md).
  "refusal_reason_plaintext_0x02",
  "refusal_reason_plaintext_0x03",
  "art_17_reason_plaintext",
  "art_18_reason_plaintext",
  // Delivery URL bodies / recipient secrets.
  "delivery_url_body",
  "recipient_secret",
] as const;

/**
 * Type-level marker for redact() helper signature. Phase E implements
 * the body; Phase A locks the signature so Phase B/C/D consumers know
 * to use it.
 */
export type RedactSignature = (input: unknown) => unknown;

/**
 * Foundation-test helper: assert a string does NOT match any PII pattern.
 *
 * Returns the first matched pattern, or `null` if the input is clean.
 * Phase A foundation test uses this on a JSON.stringify(record) sample
 * to assert PII exclusion at the type-shape level.
 */
export function findPiiMatch(haystack: string): string | null {
  for (const pattern of PII_EXCLUSION_PATTERNS) {
    if (haystack.includes(pattern)) return pattern;
  }
  return null;
}
