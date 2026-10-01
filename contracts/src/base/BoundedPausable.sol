// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IPausableSurface } from "./IPausableSurface.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";

/// @title BoundedPausable - bounded-duration auto-expiring pause base
/// @notice Concrete pausable surfaces inherit this base and override
///         `_authorizePause` (and optionally `_maxPauseDuration` and
///         `_pauseAuthorityMode`). Default `_maxPauseDuration` is the
///         operational 72-hour cap; registries override to 7 days.
///
/// @dev V1 anti-pattern guard: V1 `RevealManager.freezeReveals()` accepted
///      arbitrary durations and required manual unfreeze. V2 surfaces
///      enforce a max duration AND auto-expire on read when
///      `block.timestamp > until`.
///
/// @dev Storage layout discipline (S2-2 §1.2): `_pauses` is the only
///      storage variable here. Concrete subclasses MUST NOT reorder it
///      relative to other inherited storage. Append-only; reordering
///      breaks UUPS proxy state.
abstract contract BoundedPausable is IPausableSurface {
    struct PauseEntry {
        uint64 until;
        bytes32 reasonRef;
    }

    /// @notice Per-scope pause records.
    /// @dev SLOT 0 for this contract's storage namespace; UUPS-aware
    ///      subclasses MUST account for inherited slots.
    mapping(bytes32 => PauseEntry) internal _pauses;

    /// @notice Emit `PauseExpired` only on explicit unpause path; `isPaused`
    ///         observation does not emit (view function).
    /// @inheritdoc IPausableSurface
    function pause(bytes32 scope, uint64 until, bytes32 reasonRef) external virtual override {
        _authorizePause(scope, msg.sender);
        if (until <= block.timestamp) {
            revert PauseUntilInvalid(scope, until);
        }
        uint64 maxDuration = _maxPauseDuration();
        uint64 maxUntil = uint64(block.timestamp) + maxDuration;
        if (until > maxUntil) {
            revert PauseDurationTooLong(scope, until, maxUntil);
        }
        _pauses[scope] = PauseEntry({ until: until, reasonRef: reasonRef });
        emit PauseSet(scope, until, reasonRef, _pauseAuthorityMode(scope));
    }

    /// @inheritdoc IPausableSurface
    function unpause(bytes32 scope) external virtual override {
        _authorizePause(scope, msg.sender);
        delete _pauses[scope];
        emit PauseCleared(scope);
    }

    /// @inheritdoc IPausableSurface
    function isPaused(bytes32 scope)
        external
        view
        virtual
        override
        returns (bool active, uint64 until, bytes32 reasonRef)
    {
        PauseEntry memory entry = _pauses[scope];
        until = entry.until;
        reasonRef = entry.reasonRef;
        active = until != 0 && uint64(block.timestamp) < until;
    }

    /// @notice Subclass authorization hook. Implementations MUST revert with
    ///         `PauseUnauthorized` (or a subclass-specific error) when `caller`
    ///         is not allowed to pause/unpause `scope`. Per S2-2 §14.1A,
    ///         pause-authority validation must check that the active mode is
    ///         `Partner` (0) or `Joint` (1); `None` (2) and ShredAuthorityMode
    ///         values MUST be rejected. See `Errors.PauseAuthorityInvalid`.
    function _authorizePause(bytes32 scope, address caller) internal view virtual;

    /// @notice Subclass-supplied max pause window in seconds.
    /// @dev Default = `MAX_OPERATIONAL_PAUSE_SECONDS` (72 hours). Registry
    ///      surfaces override to `MAX_REGISTRY_PAUSE_SECONDS` (7 days);
    ///      EmergencyGovernance to `MAX_EMERGENCY_PAUSE_SECONDS` (7 days);
    ///      ChallengeRegistry may further constrain to `72 hours` per S2-2.
    function _maxPauseDuration() internal view virtual returns (uint64) {
        return PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
    }

    /// @notice Subclass-supplied authority mode for `scope` (recorded in `PauseSet`).
    /// @dev Default reports `Partner`; PDA-bound surfaces should override to
    ///      report the per-scope PDA's `pauseAuthorityMode`.
    function _pauseAuthorityMode(bytes32 scope) internal view virtual returns (PauseAuthorityMode) {
        scope; // silence unused
        return PauseAuthorityMode.Partner;
    }
}
