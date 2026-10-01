import { prepareSubmittedPda } from "../../src/pda/emit.js";
import { hashToHex32 } from "../../src/pda/pda-root.js";
import type { DeadManSwitchScaffold } from "./dead-man-switch.scaffold.js";

export const deadManSwitch: DeadManSwitchScaffold = {
  use_case: "dead_man_switch",
  archetype: "conditional_reveal_liveness",
  template_id: hashToHex32("dead_man_switch_heartbeat_release_v2"),
  template_name: "dead_man_switch_heartbeat_release_v2",
  g3_choice: "drand",
  g4_phase: 2,
  trust_tier: "B",
  reveal_condition: {
    module: "DeadManSwitch",
    evidence_template_pick: hashToHex32("heartbeat_release"),
    evidence_parameters: {
      heartbeat_interval_seconds: 2_592_000n,
      grace_window_seconds: 604_800n,
      notification_delay_seconds: 86_400n,
      beneficiary_count: 1,
      evidence_expiry_seconds: 31_536_000n,
    },
    subject_liveness_oracle_ref: "vital-records-oracle",
  },
  shred_condition: {
    mode: "P",
    spec_hash: hashToHex32("dead_man_switch_heartbeat_release_v2:shred"),
    mandatory_guardrail_present: true,
  },
  recipients: [{ role_tag: "BENEFICIARY", delivery_mode: "PASSKEY_ACCOUNT" }],
  conditional_recipients: {
    n: 2,
    k: 1,
    role_tags: ["BENEFICIARY"],
    updatable: true,
  },
  pda_updatable: true,
  conditional_recipients_updatable: true,
  emergency_response_bricking_acknowledgment: false,
  fire_time_ttl_estimate_seconds: 946_728_000n,
  reveal_challenge_window_seconds: 0n,
  shred_challenge_window_seconds: 0n,
  shred_authority: "Subject",
  legal_effect_expected: false,
  partner_id: "partner_dead_man_switch",
};

export const deadManSwitchSubmittedPda = prepareSubmittedPda(
  deadManSwitch as unknown as Record<string, unknown>,
);
