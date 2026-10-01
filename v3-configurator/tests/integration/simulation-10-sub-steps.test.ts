import { describe, expect, it } from "vitest";
import { runSimulationHarness } from "../../src/simulation/index.js";

describe("Stage 5 simulation harness", () => {
  it("runs the 10 sub-steps in deterministic §4.6 order and emits a digest", () => {
    const result = runSimulationHarness({
      fsm_reachability: {
        states: ["initial", "authorized", "delivered"],
        initial: "initial",
        transitions: [
          { from: "initial", to: "authorized" },
          { from: "authorized", to: "delivered" },
        ],
        terminal_firing_states: ["delivered"],
      },
      axis_separation: {
        reveal_terminal_states: ["delivered"],
        shred_terminal_states: ["shredded"],
      },
      gas_budget: {
        advance_fsm_worst_case_gas: 100_000,
        predicate_worst_case_gas: 50_000,
        pda_budget_gas: 200_000,
      },
      schema_compat: {
        claims: [
          {
            path: "claims.defaulted",
            type_checks_against_registry_example: true,
          },
        ],
      },
      canonical_examples: {
        examples: [
          {
            claim_path: "claims.defaulted",
            registered_valid_example_passed: true,
            registered_invalid_example_failed: true,
          },
        ],
      },
      challenge_windows: {
        zero_window_replayed: true,
        non_zero_window_replayed: true,
      },
      registry_overlay: {
        pda_root_commit_block: 100n,
        authorization_block: 102n,
        referenced_entries: [
          { registry: "OracleRegistry", entry_id: "oracle-a" },
        ],
        deprecations: [
          {
            registry: "OracleRegistry",
            entry_id: "oracle-b",
            deprecated_at_block: 101n,
          },
        ],
      },
      sd_isolation: {
        escrow_succeeds_when_sd_fails: true,
        non_escrow_only_fields: ["age_over_18"],
        audit_diff_fields: ["age_over_18"],
      },
      recipient_policy: {
        threshold: { k: 1, n: 2 },
        recipients: [
          { role_tag: "BENEFICIARY", delivery_mode: "PASSKEY_ACCOUNT" },
          { role_tag: "HEIR", delivery_mode: "PASSKEY_ACCOUNT" },
        ],
      },
      universal_tripwire_negative: {
        delivery_fired_before_on_chain_condition: false,
        delivery_fired_before_gate_eligibility: false,
      },
    });

    expect(result.ok).toBe(true);
    expect(result.steps.map((step) => step.step)).toEqual([
      "fsm-reachability",
      "axis-separation",
      "gas-budget",
      "schema-compat",
      "canonical-example-replay",
      "challenge-window-lifecycle",
      "registry-overlay",
      "sd-isolation",
      "recipient-policy",
      "universal-tripwire-negative",
    ]);
    expect(result.simulation_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
