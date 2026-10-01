// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { IConditionModule, IPaymentObligationModule } from "../engine/IConditionEngine.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

abstract contract ConditionModuleBase is
    Initializable,
    AccessControl,
    UUPSUpgradeable,
    BoundedPausable,
    IConditionModule
{
    struct ModuleConfig {
        bool configured;
        bytes32 moduleRef;
        bytes32 configDigest;
    }

    address internal _conditionEngine;
    mapping(bytes32 => ModuleConfig) internal _moduleConfigs;

    event ConditionEngineSet(address indexed conditionEngine);
    error ModulePaused(bytes32 scope);

    function __ConditionModuleBase_init(address timelock, address conditionEngine_) internal onlyInitializing {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
        _grantRole(Roles.MODULE_ADMIN_ROLE, timelock);
        _conditionEngine = conditionEngine_;
        emit ConditionEngineSet(conditionEngine_);
    }

    modifier onlyConditionEngine() {
        if (msg.sender != _conditionEngine) revert ModuleUnauthorizedCaller(msg.sender);
        _;
    }

    modifier onlyConditionEngineOrModuleAdmin() {
        if (msg.sender != _conditionEngine && !hasRole(Roles.MODULE_ADMIN_ROLE, msg.sender)) {
            revert ModuleUnauthorizedCaller(msg.sender);
        }
        _;
    }

    function configure(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config)
        external
        virtual
        onlyConditionEngineOrModuleAdmin
    {
        _requireNotPaused(authorizationId);
        bytes32 configDigest = config.length == 0 ? bytes32(0) : keccak256(config);
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: moduleRef, configDigest: configDigest });
        _configureModule(authorizationId, moduleRef, config, configDigest);
        emit ModuleConfigured(authorizationId, moduleRef, configDigest);
    }

    function advance(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        external
        virtual
        onlyConditionEngine
        returns (bool terminal)
    {
        _requireKnown(authorizationId);
        _requireNotPaused(authorizationId);
        terminal = _advanceModule(authorizationId, evidenceRef, proof);
        emit ModuleAdvanced(authorizationId, evidenceRef, terminal);
    }

    function evaluate(bytes32 authorizationId, bytes32 contextRef) external view virtual returns (bool) {
        _requireKnown(authorizationId);
        return _evaluateModule(authorizationId, contextRef);
    }

    function conditionEngine() external view returns (address) {
        return _conditionEngine;
    }

    function moduleConfig(bytes32 authorizationId) external view returns (ModuleConfig memory) {
        _requireKnown(authorizationId);
        return _moduleConfigs[authorizationId];
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32 configDigest)
        internal
        virtual
    {
        authorizationId;
        moduleRef;
        config;
        configDigest;
    }

    function _advanceModule(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        internal
        virtual
        returns (bool);

    function _evaluateModule(bytes32 authorizationId, bytes32 contextRef) internal view virtual returns (bool);

    function _requireKnown(bytes32 authorizationId) internal view {
        if (!_moduleConfigs[authorizationId].configured) revert ModuleUnknownAuthorization(authorizationId);
    }

    function _requireNotPaused(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert ModulePaused(scope);
        }
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (!hasRole(Roles.PAUSER_ROLE, caller)) revert PauseUnauthorized(scope, caller);
    }

    function _maxPauseDuration() internal pure override returns (uint64) {
        return PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
    }

    function _pauseAuthorityMode(bytes32) internal pure override returns (PauseAuthorityMode) {
        return PauseAuthorityMode.Joint;
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }
}

contract PaymentObligationModule is ConditionModuleBase, IPaymentObligationModule {
    enum ObligationStatus {
        None,
        Active,
        Paid,
        Defaulted,
        Cured
    }

    struct ObligationState {
        bytes32 authorizationId;
        uint64 dueAt;
        uint64 cureDeadline;
        uint8 status;
        uint8 trustTier;
        bytes32 defaultDigest;
        bytes32 paymentDigest;
        bytes32 configDigest;
    }

    mapping(bytes32 => ObligationState) private _obligations;
    mapping(bytes32 => bytes32) private _obligationByAuthorization;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
    }

    function registerObligation(bytes32 authorizationId, bytes32 obligationRef, bytes32 configDigest)
        external
        onlyConditionEngineOrModuleAdmin
    {
        _registerObligation(authorizationId, obligationRef, configDigest);
    }

    function configureObligation(
        bytes32 authorizationId,
        bytes32 obligationRef,
        uint64 dueAt,
        uint64 cureWindow,
        uint8 trustTier,
        bytes32 configDigest
    ) external onlyConditionEngineOrModuleAdmin {
        _registerObligation(authorizationId, obligationRef, configDigest);
        ObligationState storage state = _obligations[obligationRef];
        state.dueAt = dueAt;
        state.cureDeadline = dueAt + cureWindow;
        state.trustTier = trustTier;
    }

    /// @notice Marks a payment-obligation as observed-paid; cures a default if within window.
    /// @dev Contract-only (onlyConditionEngine). State transitions:
    ///      Active → Paid (normal payment observation); Defaulted → Cured (if
    ///      block.timestamp <= cureDeadline). Reverts on None (inactive obligation),
    ///      or on Defaulted-past-cure-window (PaymentObligationAlreadyDefaulted).
    /// @param obligationRef obligation handle.
    /// @param paymentDigest hash of the payment evidence.
    function markPaymentObserved(bytes32 obligationRef, bytes32 paymentDigest) external onlyConditionEngine {
        ObligationState storage state = _obligations[obligationRef];
        if (state.status == uint8(ObligationStatus.None)) revert PaymentObligationInactive(obligationRef);
        if (state.status == uint8(ObligationStatus.Defaulted)) {
            if (block.timestamp > state.cureDeadline) revert PaymentObligationAlreadyDefaulted(obligationRef);
            state.status = uint8(ObligationStatus.Cured);
            state.paymentDigest = paymentDigest;
            emit CureObserved(state.authorizationId, obligationRef, paymentDigest);
            return;
        }
        state.status = uint8(ObligationStatus.Paid);
        state.paymentDigest = paymentDigest;
        emit PaymentObserved(state.authorizationId, obligationRef, paymentDigest);
    }

    /// @notice Marks a payment-obligation as defaulted, starting cure window if not already.
    /// @dev Contract-only (onlyConditionEngine). Reverts if obligation is not Active OR
    ///      if a paymentDigest was already recorded (PaymentObligationEvidenceMismatch).
    ///      Sets cureDeadline = block.timestamp on first transition; subsequent Active→
    ///      Defaulted transitions preserve the original cureDeadline.
    /// @param obligationRef obligation handle.
    /// @param defaultDigest hash of the default-evidence.
    function markDefaultObserved(bytes32 obligationRef, bytes32 defaultDigest) external onlyConditionEngine {
        ObligationState storage state = _obligations[obligationRef];
        if (state.status != uint8(ObligationStatus.Active)) revert PaymentObligationInactive(obligationRef);
        if (state.paymentDigest != bytes32(0)) revert PaymentObligationEvidenceMismatch(obligationRef, defaultDigest);
        state.status = uint8(ObligationStatus.Defaulted);
        state.defaultDigest = defaultDigest;
        if (state.cureDeadline == 0) state.cureDeadline = uint64(block.timestamp);
        emit DefaultObserved(state.authorizationId, obligationRef, defaultDigest);
    }

    function obligationStatus(bytes32 obligationRef)
        external
        view
        returns (uint8 status, uint64 dueAt, uint64 cureDeadline)
    {
        ObligationState memory state = _obligations[obligationRef];
        return (state.status, state.dueAt, state.cureDeadline);
    }

    function obligationState(bytes32 obligationRef) external view returns (ObligationState memory) {
        return _obligations[obligationRef];
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32 configDigest)
        internal
        override
    {
        bytes32 obligationRef = moduleRef;
        uint64 dueAt = uint64(block.timestamp);
        uint64 cureWindow = 0;
        uint8 trustTier = 0;
        if (config.length != 0) {
            (obligationRef, dueAt, cureWindow, trustTier) = abi.decode(config, (bytes32, uint64, uint64, uint8));
        }
        _obligationByAuthorization[authorizationId] = obligationRef;
        _obligations[obligationRef] = ObligationState({
            authorizationId: authorizationId,
            dueAt: dueAt,
            cureDeadline: dueAt + cureWindow,
            status: uint8(ObligationStatus.Active),
            trustTier: trustTier,
            defaultDigest: bytes32(0),
            paymentDigest: bytes32(0),
            configDigest: configDigest
        });
    }

    function _registerObligation(bytes32 authorizationId, bytes32 obligationRef, bytes32 configDigest) private {
        _requireNotPaused(authorizationId);
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: obligationRef, configDigest: configDigest });
        _obligationByAuthorization[authorizationId] = obligationRef;
        ObligationState storage state = _obligations[obligationRef];
        state.authorizationId = authorizationId;
        state.status = uint8(ObligationStatus.Active);
        state.configDigest = configDigest;
        if (state.dueAt == 0) state.dueAt = uint64(block.timestamp);
        emit ModuleConfigured(authorizationId, obligationRef, configDigest);
    }

    function _advanceModule(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata)
        internal
        view
        override
        returns (bool)
    {
        bytes32 obligationRef = _obligationByAuthorization[authorizationId];
        ObligationState memory state = _obligations[obligationRef];
        if (state.status != uint8(ObligationStatus.Defaulted)) revert PaymentObligationInactive(obligationRef);
        if (evidenceRef != bytes32(0) && evidenceRef != state.defaultDigest) {
            revert PaymentObligationEvidenceMismatch(obligationRef, evidenceRef);
        }
        if (block.timestamp <= state.cureDeadline) revert PaymentObligationCureWindowActive(obligationRef);
        return true;
    }

    function _evaluateModule(bytes32 authorizationId, bytes32) internal view override returns (bool) {
        bytes32 obligationRef = _obligationByAuthorization[authorizationId];
        ObligationState memory state = _obligations[obligationRef];
        // slither-disable-next-line incorrect-equality -- enum-state equality (Defaulted); status is a discrete enum, not a continuous quantity
        return state.status == uint8(ObligationStatus.Defaulted) && block.timestamp > state.cureDeadline;
    }

    uint256[50] private __gap;
}
