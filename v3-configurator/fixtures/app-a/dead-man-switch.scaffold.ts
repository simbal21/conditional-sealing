// S2-4 App. A.5 — Dead-man's-switch PDA scaffold (required-fields contract).
//
// Template: `dead_man_switch_heartbeat_release_v2`.
//
// Defaults (verbatim from §App. A.5):
//   - use-case: dead-man's-switch;
//   - archetype: conditional reveal / liveness;
//   - G3: drand default for time/long-retention;
//   - condition: DeadManSwitchModule with heartbeat interval, grace window,
//     optional notification delay, optional subject liveness oracle;
//   - recipients: BENEFICIARY or SUBJECT_ALTERNATE;
//   - conditional recipients: optional but default for high-consequence release;
//   - `pda_updatable = true` for long TTL;
//   - challenge windows: zero unless external Tier B/C oracle dispute surface is meaningful;
//   - shred authority: Subject or Timelock depending on intent.
//
// Classifications (verbatim from §App. A.5):
//   - heartbeat cadence: category (c);
//   - DeadManSwitch evidence template pick: category (b) + evidence parameters: category (c);
//   - long-TTL updatability: category (a) default plus (b) pick;
//   - conditional-recipient threshold: category (c);
//   - trust tier declaration: category (b) with CF-06 enforcement.

/**
 * Required-field contract for the dead-man's-switch archetype.
 *
 * Long-TTL semantics activate CF-03 (long-TTL conditional-recipient
 * redundancy: `n >= 2k` OR `emergency_response_bricking_acknowledgment = true`)
 * and `pda_updatable = true` default per row 80.
 */
export interface DeadManSwitchScaffold {
  // archetype identity --------------------------------------------------------
  readonly use_case: "dead_man_switch";
  readonly archetype: "conditional_reveal_liveness";
  readonly template_id: string;
  readonly template_name: "dead_man_switch_heartbeat_release_v2";

  // trust + custody picks -----------------------------------------------------
  readonly g3_choice: "drand"; // default for time/long-retention
  readonly g4_phase: 2;
  readonly trust_tier: "A" | "B" | "C"; // declared per CF-06

  // condition modules ---------------------------------------------------------
  readonly reveal_condition: {
    readonly module: "DeadManSwitch";
    readonly evidence_template_pick: string; // row 62.1
    readonly evidence_parameters: {
      readonly heartbeat_interval_seconds: bigint;
      readonly grace_window_seconds: bigint;
      readonly notification_delay_seconds?: bigint;
      readonly beneficiary_count?: number;
      readonly evidence_expiry_seconds?: bigint;
    };
    /** Optional subject-liveness oracle ref. */
    readonly subject_liveness_oracle_ref?: string;
  };
  readonly shred_condition: {
    readonly mode: "P" | "F";
    readonly spec_hash: string;
    readonly mandatory_guardrail_present: true;
  };

  // recipients ---------------------------------------------------------------
  readonly recipients: ReadonlyArray<{
    readonly role_tag: "BENEFICIARY" | "SUBJECT_ALTERNATE";
    readonly delivery_mode: string;
  }>;

  // conditional recipients ---------------------------------------------------
  readonly conditional_recipients?: {
    readonly n: number;
    readonly k: number;
    readonly role_tags: ReadonlyArray<string>;
    /** CF-03 long-TTL redundancy: when n < 2k AND updatable=false, requires bricking ack. */
    readonly updatable: boolean;
  };

  // long-TTL flags -----------------------------------------------------------
  readonly pda_updatable: true; // row 80 default for long TTL
  readonly conditional_recipients_updatable: boolean;
  readonly emergency_response_bricking_acknowledgment: boolean;
  readonly fire_time_ttl_estimate_seconds: bigint;

  // challenge windows ---------------------------------------------------------
  readonly reveal_challenge_window_seconds: bigint; // zero unless external Tier B/C oracle
  readonly shred_challenge_window_seconds: bigint;

  // shred authority -----------------------------------------------------------
  readonly shred_authority: "Subject" | "Timelock";

  // legal posture -------------------------------------------------------------
  readonly legal_effect_expected: boolean;

  // partner -----------------------------------------------------------------
  readonly partner_id: string;
}
