// S2-4 §4.5 — Stage 4 cross-field rules (CF-01..CF-07).
//
// Verbatim from spec §4.5 — every rule's specification text is copied
// directly from the spec. Phase A locks the enum + descriptor metadata;
// Phase D implements the actual check functions
// (`src/validate/cross-field/cf-XX.ts`).
//
// Stage 4 evaluates ALL cross-field rules and emits ALL failures together
// (NOT short-circuit) per §4.5 + §14.2. The `cf/dispatcher.ts` in Phase D
// is the canonical orchestrator.
//
// Validation primary-failure code for CF-07 is `CF-07_MULTIPARTY_SIGNAL_DEFAULT`
// per §4.5 + §12.3.
//
// Foundation test `tests/foundation/cf-catalog.test.ts` asserts
// `CF_CATALOG.length === 7` and `CF-07` has its primary failure code.

export type CfCode = "CF-01" | "CF-02" | "CF-03" | "CF-04" | "CF-05" | "CF-06" | "CF-07";

export interface CfDescriptor {
  readonly id: CfCode;
  /** Short rule label verbatim from §4.5 header (e.g., "Art. 22 legal-effect safeguard"). */
  readonly label: string;
  /** Rule specification text verbatim from §4.5 body. */
  readonly specification: string;
  /**
   * Validation-failure primary code (mandatory for CF-07 per §4.5 +
   * §12.3; optional descriptor for CF-01..CF-06 — Phase D names them).
   */
  readonly primary_failure_code?: string;
  /**
   * Whether the rule has a per-PDA opt-out branch governed by archetype
   * template + partner acknowledgment. Currently only CF-07.
   */
  readonly has_opt_out_branch: boolean;
  /**
   * Whether the rule's class-wide opt-out (if any) requires sub-class 3
   * governance per §6.3 / §12.3.
   */
  readonly class_wide_opt_out_requires_sub_class_3: boolean;
}

/**
 * The 7-entry Stage-4 CF catalog.
 *
 * Prose is byte-exact verbatim from S2-4 §4.5 (lines 421-455).
 */
export const CF_CATALOG: readonly CfDescriptor[] = [
  {
    id: "CF-01",
    label: "Art. 22 legal-effect safeguard",
    specification:
      "If `legal_effect_expected = true` and any relevant reveal-side condition module is Tier B/C, all five conjuncts must hold: 1. `reveal_challenge_window >= archetype_floor`. 2. `ceremony_resolver.type in {human_endpoint, judicial_address}`. 3. `subject` is in `eligible_challengers_reveal`. 4. `minimum_shred_latency >= archetype_floor`. 5. `cealis_class_wide_halt_opt_out = false`. For Tier A legal-effect PDAs, the challenge window is forced zero and Art. 22 posture relies on pre-commit informed consent, chain-native trigger determinism, and PDA-permitted crypto-shred.",
    has_opt_out_branch: false,
    class_wide_opt_out_requires_sub_class_3: false,
  },
  {
    id: "CF-02",
    label: "legal-effect halt opt-out forbid",
    specification:
      "If `legal_effect_expected = true`, `cealis_class_wide_halt_opt_out` must be false regardless of trust tier.",
    has_opt_out_branch: false,
    class_wide_opt_out_requires_sub_class_3: false,
  },
  {
    id: "CF-03",
    label: "long-TTL conditional-recipient redundancy",
    specification:
      "If `fire_time_ttl_estimate > 5 years` and `conditional_recipients_updatable = false`, require `n >= 2k` or `emergency_response_bricking_acknowledgment = true`.",
    has_opt_out_branch: false,
    class_wide_opt_out_requires_sub_class_3: false,
  },
  {
    id: "CF-04",
    label: "SUBJECT_SELF liveness interlock",
    specification:
      "If any conditional recipient has `role_tag = SUBJECT_SELF`, require `delivery_mode = PASSKEY_ACCOUNT` and `subject_liveness_required_at_fire = true`. For testament-style conditions where the subject is not alive at fire, `SUBJECT_SELF` is rejected.",
    has_opt_out_branch: false,
    class_wide_opt_out_requires_sub_class_3: false,
  },
  {
    id: "CF-05",
    label: "legal-effect Phase 1 G4 forbid",
    specification:
      "If `legal_effect_expected = true` or the PDA is partner-ready, `g4_phase` must be Phase 2.",
    has_opt_out_branch: false,
    class_wide_opt_out_requires_sub_class_3: false,
  },
  {
    id: "CF-06",
    label: "trust-tier-to-oracle-tier consistency",
    specification:
      "A Tier A PDA cannot reference Tier B or Tier C oracles on the relevant axis. A Tier B PDA cannot reference Tier C oracles unless the partner explicitly upgrades the PDA to Tier C. Tier C is most permissive but carries explicit partner acknowledgment and k-of-n defaults where irreversible.",
    has_opt_out_branch: false,
    class_wide_opt_out_requires_sub_class_3: false,
  },
  {
    id: "CF-07",
    label: "irreversible-archetype MultiPartySignal default",
    specification:
      "If the PDA archetype is irreversible or high-consequence and the firing condition depends on an external event source, the PDA must use k-of-n MultiPartySignal with `k >= 2` across independent oracle operators unless the selected PDA+ archetype template explicitly permits per-PDA opt-out and the partner supplies explicit acknowledgment. Validation code: `CF-07_MULTIPARTY_SIGNAL_DEFAULT`. Pass: `k >= 2`, `k <= n`, independent oracle operators, no duplicate signer identities, oracle refs at or above declared trust tier, and signal-digest binding across all signers. Fail: missing MultiPartySignal default, `k > n`, duplicate signer identities, non-independent oracle operators, oracle refs below declared trust tier, or missing signal-digest binding. Opt-out branch: per-PDA opt-out is valid only when the PDA+ archetype template permits opt-out and the partner acknowledgment is bound into the inspection surface. Class-wide opt-out requires sub-class 3 governance.",
    primary_failure_code: "CF-07_MULTIPARTY_SIGNAL_DEFAULT",
    has_opt_out_branch: true,
    class_wide_opt_out_requires_sub_class_3: true,
  },
] as const;

/** Cross-spec invariant: catalog has exactly 7 entries. */
export const CF_CATALOG_COUNT = 7 as const;

/** Convenience: map CF code to descriptor. */
export const CF_BY_ID: ReadonlyMap<CfCode, CfDescriptor> = new Map(
  CF_CATALOG.map((desc): readonly [CfCode, CfDescriptor] => [desc.id, desc] as const),
);
