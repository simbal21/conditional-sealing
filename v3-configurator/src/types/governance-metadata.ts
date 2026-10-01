// S2-4 §6.8 — Governance metadata interface (5 sub-class rows verbatim).
//
// "S2-6 may refine the runbook details, but it MUST implement the interface
// shape below so the configurator, escalation report, and partner inspection
// surface render the same governance facts."
//
// Phase A locks the interface + the 5-row SubClassMetadata map verbatim from
// the §6.8 table. Phase D's `governance/metadata-emitter.ts` renders this
// data into partner-inspection JSON; Phase E's audit-trail records governance
// events using the on_chain_event names listed here.
//
// CRITICAL: the `inspection_visibility` prose strings are byte-exact from the
// §6.8 table. Paraphrasing risk is high — SPEC-COMPLIANCE-GUARD §19 enforces.

/**
 * Generic per-sub-class governance metadata interface per §6.8.
 *
 * Fields:
 *   - `authority_ref`: governance authority entity (e.g., TimelockController-7d,
 *     CealisSecurityMultisig + EmergencyGovernance).
 *   - `threshold_ref`: signer-threshold ref managed by S2-6 (e.g.,
 *     TIMELOCK_PROPOSER + TIMELOCK_EXECUTOR, SECURITY_MULTISIG_THRESHOLD).
 *   - `delay_seconds`: pre-execution timelock delay (0 for emergency paths).
 *   - `max_duration_seconds`: time-bounded duration for emergency / deprecation
 *     surfaces (0 when not applicable to a sub-class).
 *   - `on_chain_event`: emitted-event name(s) for queued / executed transitions.
 *   - `inspection_visibility`: partner-inspection surface visibility prose
 *     (verbatim from §6.8 — affects partner-readable rendering).
 *   - `s2_6_ceremony_ref`: cross-spec ref to S2-6 ceremony runbook (e.g.,
 *     "S2-6-CER-01" for sub-class 1 ceremony).
 */
export interface GovernanceMetadata {
  readonly authority_ref: string;
  readonly threshold_ref: string;
  readonly delay_seconds: number | string;
  readonly max_duration_seconds: number | string;
  readonly on_chain_event: string;
  readonly inspection_visibility: string;
  readonly s2_6_ceremony_ref: string;
}

/**
 * The 5-row SubClassMetadata table — verbatim from S2-4 §6.8 (lines 791-797).
 *
 * Sub-class 1: TimelockController-7d additions.
 * Sub-class 2: CealisSecurityMultisig deprecations.
 * Sub-class 3: CealisSecurityMultisig + EmergencyGovernance circuit breaker.
 * Sub-class 4: PDA+ conditional-rule constraint adjustment.
 * Sub-class 5: PDA+ conditional-rule addition.
 *
 * Note: `delay_seconds` and `max_duration_seconds` are encoded as `number`
 * when the §6.8 table gives a single integer (e.g., 604800), and as `string`
 * when the spec uses a compound or conditional form (e.g., sub-class 2:
 * "0 for non-canonical entry; 86400 for canonical-in-use entry"). Phase D
 * implementation translates the string forms into runtime conditions.
 */
export const SUB_CLASS_METADATA: ReadonlyMap<1 | 2 | 3 | 4 | 5, GovernanceMetadata> = new Map<
  1 | 2 | 3 | 4 | 5,
  GovernanceMetadata
>([
  [
    1,
    {
      authority_ref: "TimelockController-7d",
      threshold_ref: "TIMELOCK_PROPOSER plus TIMELOCK_EXECUTOR per S2-6",
      delay_seconds: 604800,
      max_duration_seconds: 0,
      on_chain_event: "PDAPlusAdditionQueued / PDAPlusAdditionExecuted",
      inspection_visibility:
        "Public queued diff before activation; partner inspection after activation.",
      s2_6_ceremony_ref: "S2-6-CER-01",
    },
  ],
  [
    2,
    {
      authority_ref: "CealisSecurityMultisig",
      threshold_ref: "SECURITY_MULTISIG_THRESHOLD per S2-6",
      delay_seconds: "0 for non-canonical entry; 86400 for canonical-in-use entry",
      max_duration_seconds: "259200 disclosure deadline; 2592000 re-deprecation cooldown",
      on_chain_event: "PDAPlusEntryDeprecated / PDAPlusDeprecationCleared",
      inspection_visibility:
        "Immediate warning on affected PDA summaries; disclosure hash shown when published.",
      s2_6_ceremony_ref: "S2-6-CER-02",
    },
  ],
  [
    3,
    {
      authority_ref: "CealisSecurityMultisig plus EmergencyGovernance",
      threshold_ref:
        "SECURITY_MULTISIG_THRESHOLD plus circuit-breaker confirmation per S2-6",
      delay_seconds: 0,
      max_duration_seconds: "7776000 unless S2-6 narrows the emergency surface",
      on_chain_event: "PDAPlusEmergencyTriggered / PDAPlusEmergencyRestored",
      inspection_visibility:
        "Immediate public emergency banner, affected surface list, restore deadline, and final restoration notice.",
      s2_6_ceremony_ref: "S2-6-CER-03",
    },
  ],
  [
    4,
    {
      authority_ref: "TimelockController-7d",
      threshold_ref: "TIMELOCK_PROPOSER plus TIMELOCK_EXECUTOR per S2-6",
      delay_seconds: 604800,
      max_duration_seconds: 0,
      on_chain_event:
        "PDAPlusConstraintAdjustmentQueued / PDAPlusConstraintAdjustmentExecuted",
      inspection_visibility:
        "Queued parameter diff before activation; applied default-table diff after activation.",
      s2_6_ceremony_ref: "S2-6-CER-04",
    },
  ],
  [
    5,
    {
      authority_ref: "RuleAdditionTimelockController plus code-release author-lock",
      threshold_ref: "RULE_ADDITION_APPROVER_THRESHOLD per S2-6",
      delay_seconds: 604800,
      max_duration_seconds: 0,
      on_chain_event: "PDAPlusRuleAdditionQueued / PDAPlusRuleActivated",
      inspection_visibility:
        "Design note, validator version, tests, activation block, and affected partner surfaces.",
      s2_6_ceremony_ref: "S2-6-CER-05",
    },
  ],
]);

/** Cross-spec invariant: exactly 5 sub-class governance metadata rows. */
export const SUB_CLASS_METADATA_COUNT = 5 as const;
