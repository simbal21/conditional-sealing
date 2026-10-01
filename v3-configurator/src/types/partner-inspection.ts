// S2-4 §7.3 — Partner-readable post-deploy PDA inspection (24 fields).
//
// "S2-4 requires a partner-readable inspection surface. S2-5 defines HTTP
// details, but S2-4 fixes content."
//
// The §7.3 prose enumerates the inspection fields via 17 grouped bullets;
// PHASE-PLAN §A12 decomposes these into 24 underlying primitive fields so
// Phase E can render each independently. The 24 fields are:
//
//   bullet 1 → partner_id, pda_id, pda_version, pda_root                (4)
//   bullet 2 → template_id, template_digest                              (2)
//   bullet 3 → schema_digest, schema_summary_human_readable              (2)
//   bullet 4 → reveal_condition_summary, shred_condition_summary         (2)
//   bullet 5 → trust_tier, oracle_refs                                   (2)
//   bullet 6 → g3_choice, g4_phase                                       (2)
//   bullet 7 → recipients_summary_with_schema_selectors                  (1)
//   bullet 8 → conditional_recipient_policy_summary                      (1)
//   bullet 9 → sd_audit_diff_non_escrow_only                             (1)
//   bullet 10 → retention_windows, challenge_windows                     (2)
//   bullet 11 → shred_authority, shred_condition                         (2)
//   bullet 12 → legal_flags_art9_qes_jurisdiction                        (1)
//                  (compound field — bundles Art. 9 basis, QES posture,
//                   legal_effect_expected, jurisdiction; rendered as
//                   structured sub-object)
//   bullet 13 → class_table_classification_per_surface                   (1)
//   bullet 14 → defaults_applied_with_override_flags                     (1)
//   bullet 15 → validation_report_digest                                 (1)
//   bullet 16 → simulation_report_digest                                 (1)
//   bullet 17 → ipfs_cids, on_chain_tx_refs                              (2)
//
// Total = 4 + 2 + 2 + 2 + 2 + 2 + 1 + 1 + 1 + 2 + 2 + 1 + 1 + 1 + 1 + 1 + 2 = 28
//
// NOTE on count reconciliation: PHASE-PLAN §A12 stated "24 required fields"
// based on a different decomposition where some primitive fields were
// merged. The COUNT IS A LOWER BOUND per spec — §7.3 is the prose authority.
// Phase A locks the FULL 28-field decomposition so no field is silently
// dropped at render time. Foundation test `partner-inspection-fields.test.ts`
// asserts every named primitive in this interface maps to a spec bullet.
//
// SPEC-COMPLIANCE-GUARD §8: "every field named in §7.3 prose is present" —
// the test below is the canonical enforcement.

import type { Bytes32 } from "../m1-imports.js";
import type { RowId } from "./class-table.js";

/**
 * Per-PDA partner-readable inspection summary.
 *
 * Phase E renders this from the frozen pda_root + IPFS canonical JSON +
 * on-chain tx history. Per §7.2: "No partner self-serve surface exists.
 * Partner-facing controls are request, review, and inspect."
 */
export interface PartnerReadableInspection {
  // bullet 1 — `partner_id`, `pda_id`, `pda_version`, `pda_root` -----------
  readonly partner_id: Bytes32;
  readonly pda_id: Bytes32;
  readonly pda_version: bigint;
  readonly pda_root: Bytes32;

  // bullet 2 — template id and template digest -----------------------------
  readonly template_id: Bytes32;
  readonly template_digest: Bytes32;

  // bullet 3 — schema digest and human-readable schema summary -------------
  readonly schema_digest: Bytes32;
  readonly schema_summary_human_readable: string;

  // bullet 4 — reveal and shred condition summaries ------------------------
  readonly reveal_condition_summary: string;
  readonly shred_condition_summary: string;

  // bullet 5 — trust tier and oracle refs ----------------------------------
  readonly trust_tier: "A" | "B" | "C";
  readonly oracle_refs: ReadonlyArray<{
    readonly oracle_id: Bytes32;
    readonly tier: "A" | "B" | "C";
    readonly schema_ref: Bytes32;
  }>;

  // bullet 6 — G3 choice and G4 phase --------------------------------------
  readonly g3_choice: "dcipher" | "drand";
  readonly g4_phase: 1 | 2;

  // bullet 7 — recipients summary and schema selectors ---------------------
  readonly recipients_summary: ReadonlyArray<{
    readonly role_tag: string;
    readonly delivery_mode: string;
    readonly schema_selector: string;
  }>;

  // bullet 8 — conditional-recipient policy summary ------------------------
  readonly conditional_recipient_policy_summary: {
    readonly n: number;
    readonly k: number;
    readonly role_summary: ReadonlyArray<string>;
    readonly updatable: boolean;
  };

  // bullet 9 — SD audit diff showing all non-`escrow_only` fields ---------
  readonly sd_audit_diff_non_escrow_only: ReadonlyArray<{
    readonly field_path: string;
    readonly sd_policy: "cleartext" | "zkp";
  }>;

  // bullet 10 — retention and challenge windows ----------------------------
  readonly retention_windows: {
    readonly retention_seconds: bigint;
    readonly minimum_shred_latency_seconds: bigint;
  };
  readonly challenge_windows: {
    readonly reveal_seconds: bigint;
    readonly shred_seconds: bigint;
  };

  // bullet 11 — shred authority and shred condition ------------------------
  readonly shred_authority: "Subject" | "Joint" | "Operator" | "Timelock" | "Disabled";
  readonly shred_condition: {
    readonly mode: "P" | "F";
    readonly spec_digest: Bytes32;
    readonly mandatory_guardrail_present: true;
  };

  // bullet 12 — legal flags, Art. 9 basis, QES posture, jurisdiction ------
  readonly legal_flags_art9_qes_jurisdiction: {
    readonly legal_effect_expected: boolean;
    readonly art_9_scoped: boolean;
    readonly art_9_basis_id: number;
    readonly qes_subject_required: boolean;
    readonly qtsp_provider_ref: Bytes32;
    readonly applicable_jurisdiction: Bytes32;
  };

  // bullet 13 — class-table classification per surface --------------------
  readonly class_table_classification_per_surface: ReadonlyMap<
    string,
    {
      readonly row_id: RowId;
      readonly category: string;
      readonly governance_sub_class: string;
    }
  >;

  // bullet 14 — defaults applied and whether partner overrode them -------
  readonly defaults_applied_with_override_flags: ReadonlyArray<{
    readonly field_path: string;
    readonly default_value: string;
    readonly applied_value: string;
    readonly overridden: boolean;
    readonly default_index_used: "use-case" | "archetype" | "neither";
  }>;

  // bullet 15 — validation report digest ---------------------------------
  readonly validation_report_digest: Bytes32;

  // bullet 16 — simulation report digest ---------------------------------
  readonly simulation_report_digest: Bytes32;

  // bullet 17 — IPFS CIDs and on-chain tx refs ---------------------------
  readonly ipfs_cids: ReadonlyArray<{
    readonly cid: string;
    readonly pin_target: "cealis_primary" | "partner_mirror" | "filecoin";
  }>;
  readonly on_chain_tx_refs: ReadonlyArray<{
    readonly chain_id: number;
    readonly tx_hash: Bytes32;
    readonly block_number: bigint;
    readonly event_name: string;
  }>;
}

/**
 * Canonical primitive-field name list — used by foundation test to
 * assert every named field in §7.3 prose maps to a TypeScript surface.
 *
 * Length = 28 (per the §7.3 decomposition documented at file top).
 */
export const PARTNER_INSPECTION_PRIMITIVE_FIELDS: readonly (keyof PartnerReadableInspection)[] = [
  "partner_id",
  "pda_id",
  "pda_version",
  "pda_root",
  "template_id",
  "template_digest",
  "schema_digest",
  "schema_summary_human_readable",
  "reveal_condition_summary",
  "shred_condition_summary",
  "trust_tier",
  "oracle_refs",
  "g3_choice",
  "g4_phase",
  "recipients_summary",
  "conditional_recipient_policy_summary",
  "sd_audit_diff_non_escrow_only",
  "retention_windows",
  "challenge_windows",
  "shred_authority",
  "shred_condition",
  "legal_flags_art9_qes_jurisdiction",
  "class_table_classification_per_surface",
  "defaults_applied_with_override_flags",
  "validation_report_digest",
  "simulation_report_digest",
  "ipfs_cids",
  "on_chain_tx_refs",
] as const;

/** Cross-spec invariant — 28 primitive fields per §7.3 decomposition. */
export const PARTNER_INSPECTION_FIELD_COUNT = 28 as const;
