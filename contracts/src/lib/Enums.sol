// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Enums - V3 lifecycle / authority / mode enums and constants
/// @notice Mirrored verbatim from S2-2 smart-contracts-spec App. A (lines 2085-2110).
///         App. A is normative per S2-2 §0.6.
///
/// @dev DRIFT GUARDS:
///   - `LifecycleState` is a 10-state enum. V1's 5-state machine is
///     forbidden in V2 contracts.
///   - `PauseAuthorityMode` has EXACTLY THREE values: `Partner`, `Joint`,
///     `None`. ShredAuthorityMode values (`Subject`, `Operator`,
///     `Timelock`, `Disabled`) MUST NOT be used as PauseAuthorityMode
///     values per §14.1A.
///   - `ShredAuthorityMode.None == 0` is an invalid sentinel (per App. A
///     line 2090 NatSpec) and is not PDA-selectable.
///   - `ConditionalRecipientMode.WalletEIP1271Reserved` (== 3) is
///     RESERVED and rejected at every PDA-registration entry point at
///     V2 launch per §3.4 / §10 mode-3-rejected guardrail.
///   - `ConditionMode.None` (== 0) is a Solidity sentinel only;
///     `pda_root` `reveal_condition_mode` / `shred_condition_mode` accept
///     only `ModeF` (1) or `ModeP` (2).
///   - `G4Phase.None` (== 0) is a Solidity sentinel only; pda registration
///     accepts only `Phase1` (1) or `Phase2` (2). Legal-effect PDAs
///     require `Phase2`.

enum CeremonyAxis {
    Reveal,
    Shred
}

enum ConditionMode {
    None, // 0 - Solidity sentinel only, not a valid pda_root mode
    ModeF, // 1 - Finite-State Machine
    ModeP // 2 - Predicate
}

enum G3Choice {
    Dcipher, // 0
    Drand // 1
}

enum G4Phase {
    None, // 0 - Solidity sentinel only, not a valid pda registration value
    Phase1, // 1 - DEV-SCAFFOLD ONLY, forbidden on legal-effect PDAs
    Phase2 // 2 - DCAP attestation, partner-runtime per Stage-0 Q-0-2
}

/// @notice Pause authority is restricted to {Partner, Joint, None} per §14.1A.
///         ShredAuthorityMode values are explicitly forbidden here.
enum PauseAuthorityMode {
    Partner, // 0
    Joint, // 1
    None // 2
}

/// @dev None == 0 is an invalid Solidity sentinel and is not PDA-selectable.
enum ShredAuthorityMode {
    None, // 0 - invalid sentinel
    Subject, // 1
    Joint, // 2
    Operator, // 3
    Timelock, // 4
    Disabled // 5
}

enum ConditionalRecipientMode {
    None, // 0 - sentinel
    PasskeyAccount, // 1 - Mode 1
    WalletEOA, // 2 - Mode 2 (EIP-712 EOA recovery)
    WalletEIP1271Reserved // 3 - RESERVED, rejected at PDA registration entry points
}

enum GateKind {
    LitV3, // 0
    Dcipher, // 1
    Drand, // 2
    G4, // 3
    ConditionalRecipient // 4
}

enum ShredState {
    None, // 0
    Requested, // 1
    Authorized, // 2
    Finalized, // 3
    Blocked, // 4
    ChallengeOpen, // 5
    Shredded // 6
}

/// @notice 10-state ConditionEngine lifecycle per S2-2 App. A.
///         V1's 5-state machine MUST NOT replace this.
enum LifecycleState {
    Unregistered, // 0
    Registered, // 1
    RevealConditionMet, // 2
    RevealChallengeOpen, // 3
    PostChallengeRevealInProgress, // 4
    RevealCompleted, // 5
    ShredConditionMet, // 6
    ShredChallengeOpen, // 7
    Shredded, // 8
    Paused // 9
}

/// @title PauseConstants - bounded-pause maximum durations
/// @notice Per S2-2 App. A lines 2108-2110.
library PauseConstants {
    /// @notice 72 hours - default operational pause cap.
    uint64 internal constant MAX_OPERATIONAL_PAUSE_SECONDS = 259200;
    /// @notice 7 days - registry pause cap.
    uint64 internal constant MAX_REGISTRY_PAUSE_SECONDS = 604800;
    /// @notice 7 days - emergency-governance pause cap.
    uint64 internal constant MAX_EMERGENCY_PAUSE_SECONDS = 604800;
}

/// @title ProtocolVersion - V3 commit_version marker
/// @notice Per S2-1 §3.4 commit_version field; current canonical = 0x0302
///         (A1+Shamir DEK lifecycle + sdMerkleRoot binding + IB-1..IB-4
///         backprop release).
library ProtocolVersion {
    uint16 internal constant BUILD_PROTOCOL_VERSION = 0x0302;
}
