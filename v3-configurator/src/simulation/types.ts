export type SimulationStepName =
  | "fsm-reachability"
  | "axis-separation"
  | "gas-budget"
  | "schema-compat"
  | "canonical-example-replay"
  | "challenge-window-lifecycle"
  | "registry-overlay"
  | "sd-isolation"
  | "recipient-policy"
  | "universal-tripwire-negative";

export interface SimulationSubStepResult {
  readonly step: SimulationStepName;
  readonly ok: boolean;
  readonly details: string;
}

export interface FsmTransition {
  readonly from: string;
  readonly to: string;
}

export interface FsmReachabilityInput {
  readonly states: readonly string[];
  readonly initial: string;
  readonly transitions: readonly FsmTransition[];
  readonly terminal_firing_states: readonly string[];
}

export interface AxisSeparationInput {
  readonly reveal_terminal_states: readonly string[];
  readonly shred_terminal_states: readonly string[];
}

export interface GasBudgetInput {
  readonly advance_fsm_worst_case_gas: bigint | number;
  readonly predicate_worst_case_gas: bigint | number;
  readonly pda_budget_gas: bigint | number;
}

export interface SchemaCompatInput {
  readonly claims: readonly {
    readonly path: string;
    readonly type_checks_against_registry_example: boolean;
  }[];
}

export interface CanonicalExampleReplayInput {
  readonly examples: readonly {
    readonly claim_path: string;
    readonly registered_valid_example_passed: boolean;
    readonly registered_invalid_example_failed: boolean;
  }[];
}

export interface ChallengeWindowLifecycleInput {
  readonly zero_window_replayed: boolean;
  readonly non_zero_window_replayed: boolean;
}

export interface RegistryDeprecation {
  readonly registry: string;
  readonly entry_id: string;
  readonly deprecated_at_block: bigint | number;
}

export interface RegistryOverlayReplayInput {
  readonly pda_root_commit_block: bigint | number;
  readonly authorization_block: bigint | number;
  readonly referenced_entries: readonly {
    readonly registry: string;
    readonly entry_id: string;
  }[];
  readonly deprecations: readonly RegistryDeprecation[];
}

export interface RegistryOverlayReplayResult {
  readonly halted: boolean;
  readonly checked_at_block: bigint;
  readonly affected_entries: readonly string[];
}

export interface SdIsolationInput {
  readonly escrow_succeeds_when_sd_fails: boolean;
  readonly non_escrow_only_fields: readonly string[];
  readonly audit_diff_fields: readonly string[];
}

export interface RecipientPolicyReplayInput {
  readonly threshold: {
    readonly k: number;
    readonly n: number;
  };
  readonly recipients: readonly {
    readonly role_tag: string;
    readonly delivery_mode: string;
  }[];
}

export interface UniversalTripwireNegativeInput {
  readonly delivery_fired_before_on_chain_condition: boolean;
  readonly delivery_fired_before_gate_eligibility: boolean;
}

export interface SimulationHarnessInput {
  readonly fsm_reachability: FsmReachabilityInput;
  readonly axis_separation: AxisSeparationInput;
  readonly gas_budget: GasBudgetInput;
  readonly schema_compat: SchemaCompatInput;
  readonly canonical_examples: CanonicalExampleReplayInput;
  readonly challenge_windows: ChallengeWindowLifecycleInput;
  readonly registry_overlay: RegistryOverlayReplayInput;
  readonly sd_isolation: SdIsolationInput;
  readonly recipient_policy: RecipientPolicyReplayInput;
  readonly universal_tripwire_negative: UniversalTripwireNegativeInput;
}

export interface SimulationHarnessResult {
  readonly ok: boolean;
  readonly steps: readonly SimulationSubStepResult[];
  readonly simulation_digest: string;
}
