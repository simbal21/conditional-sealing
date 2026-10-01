// S2-4 App. A.3 — Evidence archival PDA scaffold (required-fields contract).
//
// Template: `evidence_provenance_retention_v2`.
//
// Defaults (verbatim from §App. A.3):
//   - use-case: evidence;
//   - archetype: tamper-proof / retention;
//   - G3: dcipher for regulated evidence, drand for long archival evidence
//     where time-based retention dominates;
//   - trust tier: Tier B/C if custody oracle or evidence custodian attestation used;
//   - condition: EvidenceProvenance plus OracleAttestation or TimeLock;
//   - retention: bounded by evidence retention floors and max;
//   - challenge windows: 7 days where external oracle/custodian attestation drives legal effect;
//   - shred authority: Disabled for permanent archive or Joint for release-window archive;
//   - SD: metadata proofs possible, default `escrow_only`.
//
// Classifications (verbatim from §App. A.3):
//   - evidence retention bounds: category (a);
//   - retention value: category (c);
//   - custodian oracle pick: category (b);
//   - evidence schema SD availability: category (a);
//   - SD field mapping: category (b).

/**
 * Required-field contract for the evidence archival archetype.
 *
 * Row 67 `evidence_retention_bounds` + row 68 `archival_permanent_shred_disabled`
 * are the load-bearing platform invariants here. CF-07 multi-oracle default
 * fires when the attestation source is external oracle/custodian.
 */
export interface EvidenceArchivalScaffold {
  // archetype identity --------------------------------------------------------
  readonly use_case: "evidence";
  readonly archetype: "tamper_proof_retention";
  readonly template_id: string;
  readonly template_name: "evidence_provenance_retention_v2";

  // trust + custody picks -----------------------------------------------------
  readonly g3_choice: "dcipher" | "drand"; // regulated → dcipher; long archival → drand
  readonly g4_phase: 2;
  readonly trust_tier: "B" | "C";

  // condition modules ---------------------------------------------------------
  readonly reveal_condition: {
    readonly module: "OracleAttestation" | "TimeLock" | "Composed";
    readonly template_pick: string;
    readonly parameter_values: Record<string, string | number | bigint | boolean>;
    /** Set when condition includes OracleAttestation per A.3 default. */
    readonly oracle_attestation_refs?: ReadonlyArray<string>;
  };
  readonly shred_condition: {
    readonly mode: "P" | "F";
    readonly spec_hash: string;
    readonly mandatory_guardrail_present: true;
  };

  // retention -----------------------------------------------------------------
  readonly retention_seconds: bigint; // bounded by row 67 PDA+ floors/max
  readonly minimum_shred_latency_seconds: bigint;

  // challenge windows ---------------------------------------------------------
  readonly reveal_challenge_window_seconds: bigint; // 7 days when external oracle
  readonly shred_challenge_window_seconds: bigint;

  // shred authority -----------------------------------------------------------
  readonly shred_authority: "Disabled" | "Joint"; // Disabled for permanent; Joint for release-window
  readonly archival_permanent_shred_disabled: boolean; // row 68 — true for Disabled posture

  // SD --------------------------------------------------------------------
  readonly sd_default: "escrow_only";
  readonly sd_field_policies: Record<string, "cleartext" | "zkp" | "escrow_only">;
  readonly evidence_schema_sd_availability: boolean; // row 9 category (a)

  // legal posture -------------------------------------------------------------
  readonly legal_effect_expected: boolean; // true when external oracle drives legal effect

  // partner -----------------------------------------------------------------
  readonly partner_id: string;
}
