// S2-4 App. A.2 — Testament PDA scaffold (required-fields contract).
//
// Template: `testament_vital_records_k_of_n_v2`.
//
// Defaults (verbatim from §App. A.2):
//   - use-case: testament;
//   - archetype: irreversible personal reveal;
//   - G3: drand default;
//   - trust tier: Tier B/C vital-records oracle k-of-n;
//   - condition: MultiPartySignal over independent vital-records attestations,
//     optionally DeadManSwitch heartbeat-grace path;
//   - conditional recipients: role_tag HEIR or BENEFICIARY, `k >= 1`;
//   - `conditional_recipients_updatable = true` by default;
//   - challenge windows: zero by archetype;
//   - shred authority: Subject or Disabled depending on testament posture;
//   - long-TTL bricking acknowledgment required if immutability selected.
//
// Classifications (verbatim from §App. A.2):
//   - testament flow template pick: category (b);
//   - testament flow parameters: category (c);
//   - k-of-n MultiPartySignal: category (c) inside CF-07 default;
//   - long-TTL updatability default: category (a) metadata;
//   - `k_conditional`: category (c);
//   - base threshold 3: category (d).

/**
 * Required-field contract for the testament archetype.
 *
 * Long-TTL semantics activate CF-03 (long-TTL conditional-recipient
 * redundancy: `n >= 2k` OR `emergency_response_bricking_acknowledgment = true`)
 * and CF-07 (irreversible-archetype MultiPartySignal default — k≥2 across
 * independent oracle operators).
 */
export interface TestamentScaffold {
  // archetype identity --------------------------------------------------------
  readonly use_case: "testament";
  readonly archetype: "irreversible_personal_reveal";
  readonly template_id: string;
  readonly template_name: "testament_vital_records_k_of_n_v2";

  // trust + custody picks -----------------------------------------------------
  readonly g3_choice: "drand";
  readonly g4_phase: 2;
  readonly trust_tier: "B" | "C"; // vital-records oracle k-of-n

  // condition modules ---------------------------------------------------------
  readonly reveal_condition: {
    readonly module: "MultiPartySignal" | "Composed"; // Composed when DeadManSwitch path included
    readonly template_pick: string;
    readonly parameter_values: Record<string, string | number | bigint | boolean>;
    readonly k_of_n: { readonly k: number; readonly n: number; readonly independent_operators: true };
  };
  readonly shred_condition: {
    readonly mode: "P" | "F";
    readonly spec_hash: string;
    readonly mandatory_guardrail_present: true;
  };

  // conditional recipients ---------------------------------------------------
  readonly conditional_recipients: {
    readonly n: number; // >= 1
    readonly k: number; // 1 by default per A.2 ("k >= 1")
    readonly role_tags: ReadonlyArray<"HEIR" | "BENEFICIARY">;
    readonly updatable: true; // default per A.2
  };

  // challenge windows ---------------------------------------------------------
  readonly reveal_challenge_window_seconds: bigint; // zero by archetype
  readonly shred_challenge_window_seconds: bigint;

  // shred authority -----------------------------------------------------------
  readonly shred_authority: "Subject" | "Disabled";
  readonly emergency_response_bricking_acknowledgment: boolean; // true required if immutability chosen

  // legal posture -------------------------------------------------------------
  readonly legal_effect_expected: false; // testament is reveal, not Art. 22 trigger

  // partner + retention -------------------------------------------------------
  readonly partner_id: string;
  readonly retention_seconds: bigint;
  readonly fire_time_ttl_estimate_seconds: bigint; // typically > 5 years → CF-03 trigger
}
