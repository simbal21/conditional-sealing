// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Errors - cross-cutting custom errors imported across multiple chunks
/// @notice Place ONLY errors that surface from ≥2 contracts here. Interface-
///         specific errors (e.g., `RegistryEntryUnknown`, `ConditionUnknownAuthorization`,
///         `LitAssignmentExists`) belong on their interface, not here.
///
/// @dev Per S2-2 §1.3 every revert is a custom error - string reverts are
///      forbidden. Per internal solidity rules (not exported) §1, V2 contracts must
///      use custom errors throughout.

/// @notice Conditional-recipient Mode 3 (`WalletEIP1271Reserved`) is reserved
///         and rejected at every PDA-registration entry point at V2 launch.
/// @dev Surfaces from ConditionEngine.registerPDA + helper validators.
error Mode3Reserved();

/// @notice Phase 1 G4 is forbidden on legal-effect PDAs per S2-2 §3.4 / §F.
/// @param authorizationId The PDA registration that failed validation.
/// @param phase The supplied phase value (1 or 2 per `G4Phase`).
error LegalEffectPhaseInvalid(bytes32 authorizationId, uint8 phase);

/// @notice `cealis_class_wide_halt_opt_out == true` is forbidden when
///         `legal_effect_expected == true` per S2-2 §3.4 / §F.
/// @param authorizationId The PDA registration that failed validation.
error LegalEffectHaltOptOutForbidden(bytes32 authorizationId);

/// @notice `subject_authenticator_class == synced_passkey` is forbidden
///         when `legal_effect_expected == true` per S2-2 §3.4.
/// @param authorizationId The PDA registration that failed validation.
error LegalEffectSyncedPasskeyForbidden(bytes32 authorizationId);

/// @notice Bounded-pause `until` exceeds the per-surface maximum.
/// @dev Surfaces from every concrete `BoundedPausable` subclass.
/// @param scope The pause scope identifier.
/// @param requested The supplied `until` timestamp.
/// @param maxAllowed The maximum allowed `until` for this surface.
error PauseDurationTooLong(bytes32 scope, uint64 requested, uint64 maxAllowed);

/// @notice Pause authority mode is not `Partner` (0) or `Joint` (1) per §14.1A.
/// @dev `None` (2) and any ShredAuthorityMode value MUST be rejected.
/// @param mode The supplied PauseAuthorityMode value.
error PauseAuthorityInvalid(uint8 mode);

/// @notice `commit_version` does not match the build-pinned `BUILD_PROTOCOL_VERSION`.
/// @param got The supplied commit_version value.
/// @param expected The build-pinned canonical value (currently 0x0302).
error BuildProtocolVersionMismatch(uint16 got, uint16 expected);

/// @notice `ShredAuthorityMode.None` (== 0) is an invalid sentinel and is
///         not PDA-selectable per S2-2 App. A line 2090.
error ShredAuthorityInvalid();
