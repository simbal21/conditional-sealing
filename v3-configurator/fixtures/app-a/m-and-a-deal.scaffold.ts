// S2-4 App. A.4 — M&A deal PDA scaffold (required-fields contract).
//
// Template: `ma_deal_multiparty_closing_v2`.
//
// Defaults (verbatim from §App. A.4):
//   - use-case: M&A;
//   - archetype: multi-party commercial escrow;
//   - G3: dcipher default for regulated/commercial-EU posture;
//   - trust tier: Tier A if closing event on partner contract, Tier B/C if counsel/court/oracle attested;
//   - condition: MultiPartySignal threshold among acquirer counsel, seller
//     counsel, board representative, or registered oracle;
//   - conditional recipients: ACQUIRER_COUNSEL optional;
//   - challenge windows: zero for Tier A, 14 days for Tier B/C;
//   - jurisdiction: scalar or set-valued only if joint-escrow archetype opts in;
//   - QES: optional if §371a posture required.
//
// Classifications (verbatim from §App. A.4):
//   - MultiPartySignal threshold: category (c);
//   - jurisdiction shape: category (a), jurisdiction code pick: category (b),
//     jurisdiction set parameters: category (c) when enabled;
//   - QES pick: category (b);
//   - QTSPRegistry: category (a);
//   - commercial pricing tier pick: category (b), pricing amounts: category (c),
//     quota: category (c).

/**
 * Required-field contract for the M&A deal archetype.
 *
 * Row 70 `ma_multi_party_signal_defaults` requires k-of-n threshold defaults
 * (board/counsel/acquirer). CF-07 enforces independent operators + k≥2.
 */
export interface MAndADealScaffold {
  // archetype identity --------------------------------------------------------
  readonly use_case: "m_and_a";
  readonly archetype: "multi_party_commercial_escrow";
  readonly template_id: string;
  readonly template_name: "ma_deal_multiparty_closing_v2";

  // trust + custody picks -----------------------------------------------------
  readonly g3_choice: "dcipher";
  readonly g4_phase: 2;
  readonly trust_tier: "A" | "B" | "C";

  // condition modules ---------------------------------------------------------
  readonly reveal_condition: {
    readonly module: "MultiPartySignal";
    readonly template_pick: string;
    readonly parameter_values: Record<string, string | number | bigint | boolean>;
    readonly k_of_n: {
      readonly k: number; // >= 2 per CF-07 + row 70 defaults
      readonly n: number;
      readonly independent_operators: true;
      readonly signer_roles: ReadonlyArray<
        "ACQUIRER_COUNSEL" | "SELLER_COUNSEL" | "BOARD_REPRESENTATIVE" | "REGISTERED_ORACLE"
      >;
    };
  };
  readonly shred_condition: {
    readonly mode: "P" | "F";
    readonly spec_hash: string;
    readonly mandatory_guardrail_present: true;
  };

  // conditional recipients ---------------------------------------------------
  readonly conditional_recipients: {
    readonly n: number;
    readonly k: number;
    /** ACQUIRER_COUNSEL is optional per A.4 default. */
    readonly role_tags: ReadonlyArray<string>;
  };

  // challenge windows ---------------------------------------------------------
  readonly reveal_challenge_window_seconds: bigint; // zero for Tier A; 14 days for B/C
  readonly shred_challenge_window_seconds: bigint;

  // jurisdiction --------------------------------------------------------------
  readonly applicable_jurisdiction: {
    /** Scalar vs set per row 78 `applicable_jurisdiction_shape`. */
    readonly shape: "scalar" | "set";
    readonly scalar_code?: string; // present when shape === "scalar"
    readonly set_members?: ReadonlyArray<string>; // present when shape === "set"
    readonly set_max_size?: number;
    readonly set_required_coverage?: number;
    readonly set_min_count?: number;
  };

  // QES posture --------------------------------------------------------------
  readonly qes_subject_required: boolean;
  readonly qtsp_provider_ref: string; // zeroed digest when qes_subject_required=false

  // commercial metadata ------------------------------------------------------
  readonly pricing_tier: string; // row 87.1 PDA pick from billing catalog
  readonly pricing_amounts: {
    readonly retainer: bigint;
    readonly per_identity: bigint;
    readonly per_obligation: bigint;
    readonly per_reveal: bigint;
    readonly percentage_basis_points: number;
    readonly cap: bigint;
    readonly floor: bigint;
  };
  readonly usage_quota: { readonly per_period_seconds: bigint; readonly max_ops: number };

  // legal posture -------------------------------------------------------------
  readonly legal_effect_expected: boolean;
  readonly cealis_class_wide_halt_opt_out: false; // CF-02 if legal_effect_expected

  // partner -----------------------------------------------------------------
  readonly partner_id: string;
}
