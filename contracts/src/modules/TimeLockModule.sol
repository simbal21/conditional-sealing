// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ITimeLockModule } from "../engine/IConditionEngine.sol";
import { ConditionModuleBase } from "./PaymentObligationModule.sol";

/// @title TimeLockModule - time-bounded reveal condition
/// @notice One of the 9 ConditionEngine modules. Predicate fires when
///         block.timestamp >= targetTimestamp, optionally bounded by notAfter
///         for window semantics. Drives use cases: scheduled-publication
///         journalism (release on date X), embargo-lift archival, post-mortem
///         testament timelocks, anti-front-run DeFi delay, M&A break-period
///         expiry, vesting-cliff data releases.
/// @dev clockSource (uint8) reserved for future oracle-clock binding (Chainlink
///      / drand-time-anchor / QTSP-timestamp); current implementation uses
///      block.timestamp directly. Window mode (configureTimeWindow with
///      notAfter != 0) enables "valid between T1 and T2" patterns —
///      important for embargoed materials that should NOT be revealable after
///      a regulatory cutoff. Single-fire flag (`fired`) is informational only;
///      _isReached returns true for any subsequent calls within the window.
contract TimeLockModule is ConditionModuleBase, ITimeLockModule {
    struct TimeLockState {
        uint64 targetTimestamp;
        uint64 notAfter;
        uint8 clockSource;
        bool fired;
        bytes32 configDigest;
    }

    mapping(bytes32 => TimeLockState) private _timeLocks;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
    }

    /// @notice Configures an open-ended time-lock (no upper bound).
    /// @dev Access: onlyConditionEngineOrModuleAdmin. targetTimestamp MUST be
    ///      non-zero (revert TimeLockTargetInvalid). notAfter is set to 0
    ///      (predicate stays true forever after targetTimestamp). For window
    ///      semantics ("valid between T1 and T2"), use configureTimeWindow
    ///      instead. Overwrites any prior config — re-configurable as use case
    ///      requires (e.g., embargo extended).
    function configureTimeLock(bytes32 authorizationId, bytes32 configDigest, uint64 targetTimestamp, uint8 clockSource)
        external
        onlyConditionEngineOrModuleAdmin
    {
        if (targetTimestamp == 0) revert TimeLockTargetInvalid(authorizationId);
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: configDigest, configDigest: configDigest });
        _timeLocks[authorizationId] = TimeLockState({
            targetTimestamp: targetTimestamp,
            notAfter: 0,
            clockSource: clockSource,
            fired: false,
            configDigest: configDigest
        });
        emit TimeLockConfigured(authorizationId, targetTimestamp, clockSource);
        emit ModuleConfigured(authorizationId, configDigest, configDigest);
    }

    /// @notice Configures a bounded time-window (valid between targetTimestamp and notAfter).
    /// @dev Access: onlyConditionEngineOrModuleAdmin. Invariants: targetTimestamp != 0,
    ///      notAfter == 0 OR notAfter > targetTimestamp. Violations revert
    ///      TimeLockTargetInvalid. Use case: regulatory disclosure windows
    ///      (DORA periodic-reporting), embargoed press materials with sunset,
    ///      M&A break-fee windows. Past notAfter the predicate stays false
    ///      forever — reveal is no longer authorizable.
    function configureTimeWindow(
        bytes32 authorizationId,
        bytes32 configDigest,
        uint64 targetTimestamp,
        uint64 notAfter,
        uint8 clockSource
    ) external onlyConditionEngineOrModuleAdmin {
        if (targetTimestamp == 0 || (notAfter != 0 && notAfter <= targetTimestamp)) {
            revert TimeLockTargetInvalid(authorizationId);
        }
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: configDigest, configDigest: configDigest });
        _timeLocks[authorizationId] = TimeLockState({
            targetTimestamp: targetTimestamp,
            notAfter: notAfter,
            clockSource: clockSource,
            fired: false,
            configDigest: configDigest
        });
        emit TimeLockConfigured(authorizationId, targetTimestamp, clockSource);
        emit ModuleConfigured(authorizationId, configDigest, configDigest);
    }

    function evaluateTimeLock(bytes32 authorizationId) external view returns (bool) {
        return _evaluateModule(authorizationId, bytes32(0));
    }

    function timeLockState(bytes32 authorizationId) external view returns (TimeLockState memory) {
        _requireKnown(authorizationId);
        return _timeLocks[authorizationId];
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32 configDigest)
        internal
        override
    {
        uint64 targetTimestamp = uint64(uint256(moduleRef));
        uint64 notAfter = 0;
        uint8 clockSource = 0;
        if (config.length != 0) {
            (targetTimestamp, notAfter, clockSource) = abi.decode(config, (uint64, uint64, uint8));
        }
        if (targetTimestamp == 0 || (notAfter != 0 && notAfter <= targetTimestamp)) {
            revert TimeLockTargetInvalid(authorizationId);
        }
        _timeLocks[authorizationId] = TimeLockState({
            targetTimestamp: targetTimestamp,
            notAfter: notAfter,
            clockSource: clockSource,
            fired: false,
            configDigest: configDigest
        });
        emit TimeLockConfigured(authorizationId, targetTimestamp, clockSource);
    }

    /// @dev Internal advance: fires the time-lock if `block.timestamp >= targetTimestamp`
    ///      and `block.timestamp <= notAfter` (if notAfter != 0). Otherwise reverts
    ///      with TimeLockNotReached. Idempotent on `fired = true` for repeat calls.
    function _advanceModule(bytes32 authorizationId, bytes32, bytes calldata) internal override returns (bool) {
        TimeLockState storage state = _timeLocks[authorizationId];
        if (!_isReached(state)) {
            revert TimeLockNotReached(authorizationId, state.targetTimestamp, uint64(block.timestamp));
        }
        state.fired = true;
        emit TimeLockReached(authorizationId, uint64(block.timestamp));
        return true;
    }

    /// @dev Internal evaluate: returns true if `block.timestamp` is within the
    ///      `[targetTimestamp, notAfter]` window (notAfter=0 means no upper bound).
    ///      View function — does not mutate state.
    function _evaluateModule(bytes32 authorizationId, bytes32) internal view override returns (bool) {
        return _isReached(_timeLocks[authorizationId]);
    }

    /// @dev Window-membership check: `targetTimestamp <= block.timestamp <= notAfter`
    ///      (notAfter=0 disables the upper bound). Used by both _advanceModule and
    ///      _evaluateModule.
    function _isReached(TimeLockState memory state) private view returns (bool) {
        if (state.notAfter != 0 && block.timestamp > state.notAfter) return false;
        return block.timestamp >= state.targetTimestamp;
    }

    uint256[50] private __gap;
}
