// S2-4 App. A.1 — KYC-lending enforcement PDA scaffold (required-fields contract).
//
// Phase A locks the REQUIRED-FIELDS CONTRACT for this archetype. Phase E
// fills the BODY with concrete byte-exact values that pass Stages 1-5.
//
// Template: `kyc_lending_payment_default_v2`.
//
// Defaults (verbatim from §App. A.1):
//   - use-case: KYC-lending;
//   - archetype: enforcement;
//   - G3: dcipher default;
//   - trust tier: Tier A if partner contract state is chain-native; Tier B/C if oracle-attested;
//   - reveal condition: PaymentObligationModule terminal default;
//   - shred condition: enforcement shred predicate plus mandatory guardrail;
//   - challenge windows: zero for Tier A, 14 days for Tier B/C;
//   - G4 phase: Phase 2;
//   - `legal_effect_expected = true`;
//   - `cealis_class_wide_halt_opt_out = false`;
//   - SD: optional per-field, default `escrow_only`.
//
// Classifications (verbatim from §App. A.1):
//   - G3 choice: category (b);
//   - challenge windows: category (c) bounded by PDA+;
//   - legal-effect classification rule: category (a) + `legal_effect_expected_value`: category (b);
//   - universal tripwire: category (d);
//   - PaymentObligation template pick: category (b) + parameter values: category (c).

/**
 * Required-field contract for the KYC-lending enforcement archetype.
 *
 * Phase E populates each field with a value that passes:
 *   - Stage 1 syntax;
 *   - Stage 2 CI checks (all 20);
 *   - Stage 3 PDA+ allow-list and bounds;
 *   - Stage 4 CF checks (CF-01..CF-07 — note that for Tier A this PDA
 *     forces challenge window zero per CF-01 conjunct 1; for Tier B/C
 *     it forces ≥14 days per archetype floor);
 *   - Stage 5 simulation harness 10 sub-steps.
 *
 * Phase A foundation test asserts every field name listed below is
 * present in the Phase E fixture file `kyc-lending.ts`.
 */
export interface KycLendingScaffold {
  // archetype identity --------------------------------------------------------
  readonly use_case: "kyc-lending";
  readonly archetype: "enforcement";
  readonly template_id: string; // content-addressed digest hex string
  readonly template_name: "kyc_lending_payment_default_v2";

  // trust + custody picks -----------------------------------------------------
  readonly g3_choice: "dcipher";
  readonly g4_phase: 2;
  readonly trust_tier: "A" | "B" | "C";

  // condition modules ---------------------------------------------------------
  readonly reveal_condition: {
    readonly module: "PaymentObligation";
    readonly template_pick: string; // category (b) — content-addressed template id
    readonly parameter_values: Record<string, string | number | bigint | boolean>; // category (c)
  };
  readonly shred_condition: {
    readonly mode: "P" | "F"; // Mode P or Mode F
    readonly spec_hash: string; // hex digest
    readonly mandatory_guardrail_present: true; // CI-12 / row 22
  };

  // challenge windows ---------------------------------------------------------
  readonly reveal_challenge_window_seconds: bigint; // 0 for Tier A; >= archetype floor for B/C
  readonly shred_challenge_window_seconds: bigint;

  // legal posture -------------------------------------------------------------
  readonly legal_effect_expected: true;
  readonly cealis_class_wide_halt_opt_out: false; // CF-02 forbid

  // SD --------------------------------------------------------------------
  readonly sd_default: "escrow_only";
  readonly sd_field_policies: Record<string, "cleartext" | "zkp" | "escrow_only">;

  // partner + retention -------------------------------------------------------
  readonly partner_id: string;
  readonly retention_seconds: bigint;
  readonly minimum_shred_latency_seconds: bigint;
}
