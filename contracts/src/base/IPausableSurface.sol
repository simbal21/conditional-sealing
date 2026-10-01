// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { PauseAuthorityMode } from "../lib/Enums.sol";

/// @title IPausableSurface - bounded-duration pause discipline
/// @notice Mirrored verbatim from S2-2 App. A lines 2611-2623. Every
///         pausable contract in the V3 stack implements this interface.
///
/// @dev DRIFT GUARD vs V1: V1's `RevealManager.freezeReveals()` had no
///      upper bound on the pause window and required manual
///      `unfreezeReveals()` to clear. V2 surfaces MUST enforce a max
///      duration via subclass-supplied `_maxPauseDuration()` AND auto-expire
///      when `block.timestamp > until`. See `BoundedPausable.sol`.
interface IPausableSurface {
    /// @notice Caller lacks the role / authority to pause this scope.
    /// @param scope The pause scope identifier.
    /// @param caller The unauthorized caller address.
    error PauseUnauthorized(bytes32 scope, address caller);

    /// @notice `until` is in the past or zero.
    /// @param scope The pause scope identifier.
    /// @param until The supplied `until` timestamp.
    error PauseUntilInvalid(bytes32 scope, uint64 until);

    /// @notice `until - block.timestamp` exceeds the surface's max pause duration.
    /// @param scope The pause scope identifier.
    /// @param requestedUntil The supplied `until` timestamp.
    /// @param maxUntil The maximum allowed `until` for this surface.
    error PauseDurationTooLong(bytes32 scope, uint64 requestedUntil, uint64 maxUntil);

    /// @notice Pause activated for `scope` until `until` with `reasonRef`.
    /// @param scope The pause scope identifier.
    /// @param until The (validated) auto-expiry timestamp.
    /// @param reasonRef A 32-byte reason reference (e.g., disclosure CID hash).
    /// @param authorityMode The authority mode under which the pause was set.
    event PauseSet(bytes32 indexed scope, uint64 until, bytes32 reasonRef, PauseAuthorityMode authorityMode);

    /// @notice Pause cleared explicitly via `unpause`.
    event PauseCleared(bytes32 indexed scope);

    /// @notice Pause auto-expired (read-side observation).
    event PauseExpired(bytes32 indexed scope, uint64 expiredAt);

    /// @notice Set a pause on `scope` until `until`.
    /// @param scope The pause scope identifier.
    /// @param until Unix-seconds timestamp when the pause auto-expires.
    /// @param reasonRef A 32-byte reason reference.
    function pause(bytes32 scope, uint64 until, bytes32 reasonRef) external;

    /// @notice Clear an active pause on `scope`.
    function unpause(bytes32 scope) external;

    /// @notice Read pause state for `scope`. Returns `(false, 0, 0x0)` if not paused
    ///         OR if the pause has auto-expired.
    /// @param scope The pause scope identifier.
    /// @return active True iff the pause is currently active (not expired).
    /// @return until The recorded `until` (zero when no pause was ever set; non-zero
    ///         and in the past when auto-expired).
    /// @return reasonRef The recorded reason reference.
    function isPaused(bytes32 scope) external view returns (bool active, uint64 until, bytes32 reasonRef);
}
