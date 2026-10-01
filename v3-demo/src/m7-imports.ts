// @cealis/v3-demo/m7-imports — typed re-export facade for @cealis/v3-ops.
//
// 4 CEREMONIES referenced by PHASE-PLAN §3:
//   1. shred-trigger      → ShredTriggerCeremony (class)        — Round 2
//   2. pause-activation   → PauseActivationCeremony (class)     — Phase E halt-activation
//   3. registry-deprecation → NOT A SINGLE CLASS (see the internal integration-gap log):
//        - PluginVersionUpdateCeremony     → refusal code 0x06 plugin_deprecated
//        - G4AuthorityRotationCeremony     → refusal code 0x07 authority_deprecated
//        - DslVersionUpdateCeremony        → refusal code 0x08 dsl_deprecated
//        - OracleRotationCeremony          → refusal code 0x09 oracle_deprecated
//   4. refusal-escalation → NOT A TS CLASS (runbook only at
//        runbooks/incident-refusal-escalation.md). Phase E orchestrates
//        the 10-code parameterized table directly using G4 mock injection.
//
// All 17 upstream ceremony classes are re-exported here; round + cross-round
// code picks the right one(s). Each ceremony class is constructed with
// (chain client, ceremony id, dry-run flag) — see Ceremony / makeContext
// from `@cealis/v3-ops`.

export {
  // Core ceremony infrastructure.
  Ceremony,
  makeContext,
  delayForPath,
  proposalHash,
  generateCeremonyId,
  // Authority enums + vault adapter (internal integration-gap close, 2026-05-14):
  //   - ShredAuthority — 5-mode enum (Subject / Joint / Operator / Timelock /
  //     Disabled) used to construct `ShredTriggerInput.authorityMode`.
  //   - PauseAuthority — analogous 4-mode enum for PauseActivation /
  //     PauseDeactivation ceremonies (kept symmetric for downstream reuse).
  //   - makeDryRunVaultClient — factory for in-memory vault client used by
  //     Round 2 / 2b dry-run pathways.
  // Phase A no-touch zone amended per an internal integration-gap item's explicit
  // authorization (back-prop target).
  ShredAuthority,
  PauseAuthority,
  makeDryRunVaultClient,
  // Round 2 + 2b (shred trigger).
  ShredTriggerCeremony,
  // Phase E halt-activation (pause M2 contracts before ingestion attempt).
  PauseActivationCeremony,
  PauseDeactivationCeremony,
  // Phase E refusal-escalation 0x06–0x09 (registry deprecation routes).
  PluginVersionUpdateCeremony,
  G4AuthorityRotationCeremony,
  DslVersionUpdateCeremony,
  OracleRotationCeremony,
  // Adjacent ceremonies (re-exported for completeness; not directly
  // invoked by M8 round/cross-round code).
  RegistryAdditionCeremony,
  G4BinaryHashUpdateCeremony,
  OracleOnboardingCeremony,
  QtspOnboardingCeremony,
  QtspRootRotationCeremony,
  WasmPredicateWhitelistUpdateCeremony,
  ReKeyStanzaAdditionCeremony,
  PdaPlusGovernanceUpdateCeremony,
  Phase1To2CutoverCeremony,
  GovernancePhase2TransitionCeremony,
  ChallengeResolutionCeremony,
  DisasterRecoveryCeremony,
  VaultOperatorTransitionCeremony,
  // Validation helper.
  checkPhase2VerificationGate,
} from "@cealis/v3-ops";

export type {
  // Internal integration-gap close: VaultClient interface type re-export (2026-05-14).
  VaultClient,
  CeremonyRunArgs,
  CeremonyOutcome,
  CeremonyLifecycleStage,
  ChainClient,
  TimelockOperation,
  ShredTriggerInput,
  PauseActivationInput,
  PauseDeactivationInput,
  PluginVersionUpdateInput,
  G4AuthorityRotationInput,
  DslVersionUpdateInput,
  OracleRotationInput,
  RegistryAddProposalInput,
  G4BinaryHashUpdateInput,
  OracleOnboardingInput,
  QtspOnboardingInput,
  QtspRootRotationInput,
  WasmPredicateWhitelistInput,
  ReKeyStanzaAdditionInput,
  PdaPlusGovernanceUpdateInput,
  Phase1To2CutoverInput,
  GovernancePhase2TransitionInput,
  ChallengeResolutionInput,
  ChallengeResolverAction,
  DisasterRecoveryInput,
  DisasterAffectedSurface,
  VaultOperatorTransitionInput,
} from "@cealis/v3-ops";

// Catalog + registry helpers (ceremony list, V3 registry list).
export {
  CEREMONY_CATALOG,
  findCeremony,
  ceremonyAtNumber,
  FIVE_V3_REGISTRIES,
  ADJACENT_REGISTRY_SURFACES,
  isV3Registry,
} from "@cealis/v3-ops";
export type { V3Registry } from "@cealis/v3-ops";

// Refusal-code escalation map: 0x06–0x09 → ceremony class name.
//
// Used by Phase E refusal-escalation cross-round parameterized table runner.
// Round 1 + 3 do not consume this map.
export const REFUSAL_DEPRECATION_CEREMONY_MAP = {
  0x06: "PluginVersionUpdateCeremony", // plugin_deprecated
  0x07: "G4AuthorityRotationCeremony", // authority_deprecated
  0x08: "DslVersionUpdateCeremony", // dsl_deprecated
  0x09: "OracleRotationCeremony", // oracle_deprecated
} as const;
