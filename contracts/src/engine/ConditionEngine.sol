// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { IBaseRegistry } from "../base/IBaseRegistry.sol";
import {
    CeremonyAxis,
    ConditionMode,
    ConditionalRecipientMode,
    G4Phase,
    LifecycleState,
    PauseAuthorityMode,
    PauseConstants,
    ProtocolVersion,
    ShredAuthorityMode
} from "../lib/Enums.sol";
import { BuildProtocolVersionMismatch, LegalEffectSyncedPasskeyForbidden } from "../lib/Errors.sol";
import { Roles } from "../lib/Roles.sol";
import { AxisConfig, FSMAdvanceResult, LegalFlags, PDARegistration, RegistryRefs } from "../lib/Structs.sol";
import { ICealisIdentifierHelpers } from "../helpers/ICealisIdentifierHelpers.sol";
import { IClaimDSL, IConditionEngine, IConditionModule, IFSMInterpreter } from "./IConditionEngine.sol";

interface IG4RefusalRegistryD2 {
    function refusalState(bytes32 authorizationId)
        external
        view
        returns (bool refused, uint8 reasonCode, bool encrypted);
}

interface IShredRegistryD2 {
    function recordShredAuthorized(
        bytes32 authorizationId,
        bytes32 hCommit,
        uint32 challengeWindow,
        bytes32 conditionRef
    ) external;
    function isShredded(bytes32 hCommit) external view returns (bool);
}

interface IFSMTerminalView {
    function isTerminal(bytes32 authorizationId, CeremonyAxis axis) external view returns (bool);
}

interface IChallengeRegistryD2 {
    // Mirrors ChallengeRegistry.ChallengeStatus: None,Open,ConfirmedNoIntervention,Halted,Expired,Withdrawn,Dismissed
    function challengeStatus(bytes32 authorizationId, CeremonyAxis axis) external view returns (uint8);
}

/// @title ConditionEngine - canonical V2 reveal/shred tripwire
/// @notice Implements the D1 `IConditionEngine` surface and owns the only
///         `RevealAuthorized` / `ShredAuthorized` event path for D2.
contract ConditionEngine is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable, ReentrancyGuardTransient, IConditionEngine {
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);
    uint8 private constant SYNCED_PASSKEY_CLASS = 0x03;

    error ConditionQesQtspMissing(bytes32 authorizationId);
    error ConditionArt9BasisMissing(bytes32 authorizationId);
    error ConditionG4Refused(bytes32 authorizationId, uint8 reasonCode);
    error ConditionUnauthorizedShredRegistry(address caller);
    error ConditionEmitterExtractionNotConfigured();
    /// @notice F-2: the reveal challenge window has not closed and the
    ///         ChallengeRegistry has not recorded ConfirmedNoIntervention.
    error ConditionChallengeNotResolved(bytes32 authorizationId, CeremonyAxis axis);
    /// @notice F-2: a challenge is still Open in the ChallengeRegistry; the
    ///         OPERATOR cannot stomp the dispute by forcing post-challenge reveal.
    error ConditionChallengeStillOpen(bytes32 authorizationId, CeremonyAxis axis);
    /// @notice BR-D: minimumShredLatency (or challenge window) below the protocol
    ///         floor for a non-Disabled shred-authority PDA.
    error ConditionShredLatencyBelowFloor(bytes32 authorizationId, uint64 supplied, uint64 floor);

    /// @dev BR-D: protocol-wide minimum shred latency for any non-Disabled
    ///      shred-authority PDA. Forecloses a compromised ORCHESTRATOR from
    ///      registering hostile PDAs with latency=0 + window=0 for an immediate
    ///      shred. 24h gives off-chain monitors / the subject a guaranteed
    ///      window to observe and challenge a shred authorization. Design-
    ///      sensitive value tracked for Simon's ratification (see fix note).
    uint64 private constant MIN_SHRED_LATENCY_FLOOR = 1 days;
    /// @dev BR-D: minimum shred challenge window for non-Disabled shred-authority
    ///      PDAs so a challenge can actually be opened before finalization.
    uint32 private constant MIN_SHRED_CHALLENGE_WINDOW = 1 days;
    /// @dev Mirrors ChallengeRegistry.ChallengeStatus index for ConfirmedNoIntervention.
    uint8 private constant CHALLENGE_STATUS_OPEN = 1;
    uint8 private constant CHALLENGE_STATUS_CONFIRMED_NO_INTERVENTION = 2;

    struct EngineConfig {
        address timelock;
        address helpers;
        address fsmInterpreter;
        address claimDSL;
        address attestationGate;
        address challengeRegistry;
        address shredRegistry;
        address g4RefusalRegistry;
        address gateRecipientPubkeyRegistry;
        address litV3Assignment;
        address supersededCommitRegistry;
        address pluginHashRegistry;
        address g4AuthorityRegistry;
        address dslVersionRegistry;
        address oracleRegistry;
        address qtspRegistry;
        address oracleSchemaRegistry;
        address[9] conditionModules;
    }

    struct PdaRecord {
        bytes32 hCommit;
        bytes32 pdaRoot;
        bytes32 partnerId;
        AxisConfig revealAxis;
        AxisConfig shredAxis;
        RegistryRefs registryRefs;
        LegalFlags legalFlags;
        PauseAuthorityMode pauseAuthorityMode;
        ShredAuthorityMode shredAuthorityMode;
        uint64 minimumShredLatency;
        bytes32 conditionalRecipientPolicyDigest;
        LifecycleState lifecycle;
        LifecycleState pausedBaseState;
        bool registered;
        bool postChallengeReveal;
        bool revealAuthorized;
        // BR-H: block at which the PDA was registered. Used as the at-authorization
        // anchor for registry-validity probes (not block.number), so a registry
        // entry tombstoned after authorization does not retroactively break an
        // in-flight ceremony (S2-2 §1080/§1115).
        uint64 registrationBlock;
        // F-2: timestamp at which the reveal was authorized; the reveal challenge
        // window runs from here. Used to gate markChallengeResolved.
        uint64 revealAuthorizedAt;
    }

    ICealisIdentifierHelpers private _helpers;
    IFSMInterpreter private _fsmInterpreter;
    IClaimDSL private _claimDSL;
    address private _attestationGate;
    address private _challengeRegistry;
    address private _shredRegistry;
    address private _g4RefusalRegistry;
    address private _gateRecipientPubkeyRegistry;
    address private _litV3Assignment;
    address private _supersededCommitRegistry;
    address private _pluginHashRegistry;
    address private _g4AuthorityRegistry;
    address private _dslVersionRegistry;
    address private _oracleRegistry;
    address private _qtspRegistry;
    address private _oracleSchemaRegistry;
    address[9] private _conditionModules;

    mapping(bytes32 => PdaRecord) private _records;
    mapping(bytes32 => bytes32) private _authorizationByHCommit;

    event ShredRegistrySet(address indexed shredRegistry);
    event ChallengeAdvanced(bytes32 indexed authorizationId, CeremonyAxis indexed axis, LifecycleState newState);
    event RevealCompleted(bytes32 indexed authorizationId, bytes32 deliveryDigest);

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(EngineConfig calldata config) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, config.timelock);
        _grantRole(Roles.UPGRADER_ROLE, config.timelock);
        _grantRole(Roles.PAUSER_ROLE, config.timelock);
        _grantRole(Roles.MODULE_ADMIN_ROLE, config.timelock);

        _helpers = ICealisIdentifierHelpers(config.helpers);
        _fsmInterpreter = IFSMInterpreter(config.fsmInterpreter);
        _claimDSL = IClaimDSL(config.claimDSL);
        _attestationGate = config.attestationGate;
        _challengeRegistry = config.challengeRegistry;
        _shredRegistry = config.shredRegistry;
        _g4RefusalRegistry = config.g4RefusalRegistry;
        _gateRecipientPubkeyRegistry = config.gateRecipientPubkeyRegistry;
        _litV3Assignment = config.litV3Assignment;
        _supersededCommitRegistry = config.supersededCommitRegistry;
        _pluginHashRegistry = config.pluginHashRegistry;
        _g4AuthorityRegistry = config.g4AuthorityRegistry;
        _dslVersionRegistry = config.dslVersionRegistry;
        _oracleRegistry = config.oracleRegistry;
        _qtspRegistry = config.qtspRegistry;
        _oracleSchemaRegistry = config.oracleSchemaRegistry;
        _conditionModules = config.conditionModules;
    }

    /// @notice Sets (or clears) the ShredRegistry contract address.
    /// @dev DEFAULT_ADMIN_ROLE only (held by TimelockController post-deploy per
    ///      internal solidity rules §1). Passing address(0) disables the
    ///      ShredRegistry callout on authorizeShred (test/dev mode).
    /// @param shredRegistry_ ShredRegistry proxy address or zero.
    function setShredRegistry(address shredRegistry_) external onlyRole(Roles.DEFAULT_ADMIN_ROLE) {
        _shredRegistry = shredRegistry_;
        emit ShredRegistrySet(shredRegistry_);
    }

    /// @notice Registers a new PDA for a given authorization.
    /// @dev ORCHESTRATOR_ROLE only. Idempotent on (authorizationId): re-registration
    ///      reverts with ConditionAlreadyRegistered. Validates that hCommitFields.pdaRoot
    ///      equals the helper-computed PdaRoot, and that all referenced registries are
    ///      consistent (per _validateRegistration).
    /// @param registration packed PdaRootFields + HCommitFields + reveal/shred axes +
    ///                     registry refs + legal flags.
    function registerPDA(PDARegistration calldata registration) external onlyRole(Roles.ORCHESTRATOR_ROLE) {
        bytes32 authorizationId = registration.hCommitFields.authorizationId;
        if (authorizationId == bytes32(0)) revert ConditionUnknownAuthorization(authorizationId);
        if (_records[authorizationId].registered) revert ConditionAlreadyRegistered(authorizationId);

        bytes32 computedPdaRoot = _helpers.computePdaRoot(registration.pdaRootFields);
        if (registration.hCommitFields.pdaRoot != computedPdaRoot) {
            revert ConditionHCommitPdaRootMismatch(registration.hCommitFields.pdaRoot, computedPdaRoot);
        }
        _validateRegistration(authorizationId, registration);

        bytes32 hCommit = _helpers.computeHCommit(registration.hCommitFields);
        PdaRecord storage record = _records[authorizationId];
        record.hCommit = hCommit;
        record.pdaRoot = computedPdaRoot;
        record.partnerId = registration.pdaRootFields.partnerId;
        record.revealAxis = registration.revealAxis;
        record.shredAxis = registration.shredAxis;
        record.registryRefs = registration.registryRefs;
        record.legalFlags = registration.legalFlags;
        record.pauseAuthorityMode = registration.pauseAuthorityMode;
        record.shredAuthorityMode = _decodeShredAuthority(registration.hCommitFields.shredAuthorityId);
        record.minimumShredLatency = registration.pdaRootFields.minimumShredLatency;
        record.conditionalRecipientPolicyDigest = registration.conditionalRecipientPolicyDigest;
        record.lifecycle = LifecycleState.Registered;
        record.registered = true;
        record.registrationBlock = uint64(block.number);
        _authorizationByHCommit[hCommit] = authorizationId;

        emit PDARegistered(authorizationId, hCommit, computedPdaRoot, registration.pdaRootFields.partnerId);
        emit LifecycleStateChanged(authorizationId, LifecycleState.Unregistered, LifecycleState.Registered);
    }

    /// @notice Authorizes a reveal for a registered PDA, gated by the reveal-axis
    ///         predicate evaluation.
    /// @dev Permissionless by design: any caller may trigger evaluation if they supply
    ///      a valid evidenceRef (S2-2 §10.4 #1; the access decision is in the predicate,
    ///      not in caller identity). Guarded by ReentrancyGuardTransient (EIP-1153)
    ///      against FSMInterpreter callback reentry. Emits RevealAuthorized on success;
    ///      transitions lifecycle to RevealConditionMet → RevealChallengeOpen (or
    ///      PostChallengeRevealInProgress if challengeWindow==0).
    /// @param authorizationId PDA identifier returned by registerPDA.
    /// @param evidenceRef predicate input (interpreted by the condition module).
    // slither-disable-next-line reentrancy-no-eth -- guarded by nonReentrant (OZ ReentrancyGuardTransient, EIP-1153); Slither's detector does not model transient-storage guards. Call targets (_evaluateAxis→FSMInterpreter) are Cealis-governed.
    function authorizeReveal(bytes32 authorizationId, bytes32 evidenceRef) external nonReentrant {
        PdaRecord storage record = _requireAuthorization(authorizationId);
        _requireRevealPreconditions(authorizationId, record);
        bytes32 conditionRef = _evaluateAxis(authorizationId, CeremonyAxis.Reveal, record.revealAxis, evidenceRef);

        record.revealAuthorized = true;
        emit RevealAuthorized(
            authorizationId,
            record.hCommit,
            record.pdaRoot,
            uint64(block.number),
            uint64(block.timestamp),
            record.revealAxis.challengeWindow,
            conditionRef
        );
        record.revealAuthorizedAt = uint64(block.timestamp);
        _transition(authorizationId, record, LifecycleState.RevealConditionMet);
        if (record.revealAxis.challengeWindow == 0) {
            record.postChallengeReveal = true;
            _transition(authorizationId, record, LifecycleState.PostChallengeRevealInProgress);
        } else {
            _transition(authorizationId, record, LifecycleState.RevealChallengeOpen);
        }
    }

    /// @notice Authorizes a shred for a registered PDA, gated by the shred-axis
    ///         predicate evaluation.
    /// @dev Permissionless by design (per shred authority-mode in PDA — Subject/Joint/
    ///      Operator/Timelock/Disabled per S2-6 §11.1-2). Reentrancy-guarded.
    ///      Emits ShredAuthorized; transitions lifecycle to ShredConditionMet
    ///      → ShredChallengeOpen (if challengeWindow > 0). If a ShredRegistry is
    ///      configured, calls recordShredAuthorized to cascade off-chain shred actions.
    /// @param authorizationId PDA identifier returned by registerPDA.
    /// @param evidenceRef predicate input (interpreted by the shred condition module).
    // slither-disable-next-line reentrancy-no-eth -- guarded by nonReentrant (OZ ReentrancyGuardTransient, EIP-1153); Slither's detector does not model transient-storage guards. Call targets (FSMInterpreter, ShredRegistry) are Cealis-governed.
    function authorizeShred(bytes32 authorizationId, bytes32 evidenceRef) external nonReentrant {
        PdaRecord storage record = _requireAuthorization(authorizationId);
        _requireShredPreconditions(authorizationId, record);
        bytes32 conditionRef = _evaluateAxis(authorizationId, CeremonyAxis.Shred, record.shredAxis, evidenceRef);

        emit ShredAuthorized(
            authorizationId,
            record.hCommit,
            record.pdaRoot,
            uint64(block.number),
            uint64(block.timestamp),
            record.shredAxis.challengeWindow,
            conditionRef
        );
        _transition(authorizationId, record, LifecycleState.ShredConditionMet);
        if (_shredRegistry != address(0)) {
            IShredRegistryD2(_shredRegistry)
                .recordShredAuthorized(authorizationId, record.hCommit, record.shredAxis.challengeWindow, conditionRef);
        }
        if (record.shredAxis.challengeWindow != 0) {
            _transition(authorizationId, record, LifecycleState.ShredChallengeOpen);
        }
    }

    /// @notice Advances the FSM state for a given (authorization, axis) by one transition.
    /// @dev Permissionless per-spec — anyone can submit a valid transition proof.
    ///      Bounded by `_requireNotPaused(authorizationId)` (per-authorization halt) +
    ///      axis-specific reveal/shred preconditions. Delegates to FSMInterpreter; on
    ///      validate-failure FSMInterpreter reverts.
    /// @param authorizationId target PDA authorization.
    /// @param axis CeremonyAxis.Reveal or CeremonyAxis.Shred.
    /// @param transitionId requested transition identifier.
    /// @param attestationDigest oracle attestation hash (bound at evaluate time).
    /// @param transitionProof FSM transition proof bytes.
    /// @return result FSMAdvanceResult struct with new state + emitted events.
    function advanceFSM(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 transitionId,
        bytes32 attestationDigest,
        bytes calldata transitionProof
    ) external returns (FSMAdvanceResult memory result) {
        PdaRecord storage record = _requireAuthorization(authorizationId);
        _requireNotPaused(authorizationId);
        if (axis == CeremonyAxis.Reveal) {
            _requireRevealPreconditions(authorizationId, record);
        } else {
            _requireShredPreconditions(authorizationId, record);
        }
        return _fsmInterpreter.advanceFSM(
            authorizationId, axis, msg.sender, transitionId, attestationDigest, transitionProof
        );
    }

    /// @notice Advances a PDA past its open challenge window to the post-challenge
    ///         reveal state (or back to ShredConditionMet for the shred axis).
    /// @dev OPERATOR_ROLE. F-2: for the reveal axis this is NOT an unconditional
    ///      OPERATOR override. It requires EITHER (a) the challenge window has
    ///      elapsed (block.timestamp past revealAuthorizedAt + challengeWindow)
    ///      with no challenge still Open in the bound ChallengeRegistry, OR (b)
    ///      the bound ChallengeRegistry has recorded ConfirmedNoIntervention for
    ///      (authorizationId, Reveal) by the per-PDA CHALLENGE_RESOLVER_ROLE.
    ///      A challenge that is still Open hard-blocks the override so an OPERATOR
    ///      cannot stomp a live dispute and force the reveal.
    function markChallengeResolved(bytes32 authorizationId, CeremonyAxis axis) external onlyRole(Roles.OPERATOR_ROLE) {
        PdaRecord storage record = _requireAuthorization(authorizationId);
        if (axis == CeremonyAxis.Reveal) {
            if (record.lifecycle != LifecycleState.RevealChallengeOpen) {
                revert ConditionChallengeWindowActive(authorizationId, axis);
            }
            _requireRevealChallengeCleared(authorizationId, record);
            record.postChallengeReveal = true;
            _transition(authorizationId, record, LifecycleState.PostChallengeRevealInProgress);
        } else {
            if (record.lifecycle != LifecycleState.ShredChallengeOpen) {
                revert ConditionChallengeWindowActive(authorizationId, axis);
            }
            _transition(authorizationId, record, LifecycleState.ShredConditionMet);
        }
        emit ChallengeAdvanced(authorizationId, axis, record.lifecycle);
    }

    /// @dev F-2 gate: the reveal challenge may only be force-resolved when the
    ///      window has elapsed AND no challenge is still Open, OR the bound
    ///      ChallengeRegistry has affirmatively recorded ConfirmedNoIntervention.
    function _requireRevealChallengeCleared(bytes32 authorizationId, PdaRecord storage record) private view {
        uint8 status = _challengeStatus(authorizationId, CeremonyAxis.Reveal);
        // Path (b): resolver affirmatively cleared the challenge.
        if (status == CHALLENGE_STATUS_CONFIRMED_NO_INTERVENTION) return;
        // A challenge still Open hard-blocks any operator override.
        if (status == CHALLENGE_STATUS_OPEN) {
            revert ConditionChallengeStillOpen(authorizationId, CeremonyAxis.Reveal);
        }
        // Path (a): window must have elapsed (no open challenge to begin with).
        uint64 windowEnd = record.revealAuthorizedAt + uint64(record.revealAxis.challengeWindow);
        if (block.timestamp <= windowEnd) {
            revert ConditionChallengeNotResolved(authorizationId, CeremonyAxis.Reveal);
        }
    }

    function _challengeStatus(bytes32 authorizationId, CeremonyAxis axis) private view returns (uint8) {
        if (_challengeRegistry == address(0)) return 0;
        try IChallengeRegistryD2(_challengeRegistry).challengeStatus(authorizationId, axis) returns (uint8 status) {
            return status;
        } catch {
            return 0;
        }
    }

    function recordRevealCompleted(bytes32 authorizationId, bytes32 deliveryDigest)
        external
        onlyRole(Roles.ORCHESTRATOR_ROLE)
    {
        PdaRecord storage record = _requireAuthorization(authorizationId);
        if (record.lifecycle != LifecycleState.PostChallengeRevealInProgress) {
            revert ConditionChallengeWindowActive(authorizationId, CeremonyAxis.Reveal);
        }
        record.postChallengeReveal = false;
        _transition(authorizationId, record, LifecycleState.RevealCompleted);
        emit RevealCompleted(authorizationId, deliveryDigest);
    }

    function recordShredFinalized(bytes32 authorizationId) external {
        if (msg.sender != _shredRegistry) revert ConditionUnauthorizedShredRegistry(msg.sender);
        PdaRecord storage record = _requireAuthorization(authorizationId);
        record.postChallengeReveal = false;
        _transition(authorizationId, record, LifecycleState.Shredded);
    }

    function canGatesSign(bytes32 authorizationId) external view returns (bool) {
        PdaRecord memory record = _records[authorizationId];
        return record.registered && record.lifecycle == LifecycleState.PostChallengeRevealInProgress
            && !_isPausedView(authorizationId) && !_hasBlockingRefusal(authorizationId)
            && !_isShreddedView(record.hCommit);
    }

    function postChallengeRevealInProgress(bytes32 authorizationId) external view returns (bool) {
        PdaRecord memory record = _records[authorizationId];
        return record.postChallengeReveal && record.lifecycle == LifecycleState.PostChallengeRevealInProgress;
    }

    function lifecycleState(bytes32 authorizationId) external view returns (LifecycleState) {
        return _records[authorizationId].lifecycle;
    }

    function hCommitForAuthorization(bytes32 authorizationId) external view returns (bytes32) {
        PdaRecord memory record = _records[authorizationId];
        if (!record.registered) revert ConditionUnknownAuthorization(authorizationId);
        return record.hCommit;
    }

    function authorizationForHCommit(bytes32 hCommit) external view returns (bytes32) {
        bytes32 authorizationId = _authorizationByHCommit[hCommit];
        if (authorizationId == bytes32(0)) revert ConditionShredded(hCommit);
        return authorizationId;
    }

    function pdaShredAuthority(bytes32 authorizationId) external view returns (ShredAuthorityMode) {
        PdaRecord memory record = _records[authorizationId];
        if (!record.registered) revert ConditionUnknownAuthorization(authorizationId);
        return record.shredAuthorityMode;
    }

    function pdaMinimumShredLatency(bytes32 authorizationId) external view returns (uint64) {
        PdaRecord memory record = _records[authorizationId];
        if (!record.registered) revert ConditionUnknownAuthorization(authorizationId);
        return record.minimumShredLatency;
    }

    function pdaRecord(bytes32 authorizationId) external view returns (PdaRecord memory) {
        PdaRecord memory record = _records[authorizationId];
        if (!record.registered) revert ConditionUnknownAuthorization(authorizationId);
        return record;
    }

    function pause(bytes32 scope, uint64 until, bytes32 reasonRef) external override {
        _authorizePause(scope, msg.sender);
        if (until <= block.timestamp) revert PauseUntilInvalid(scope, until);
        uint64 maxUntil = uint64(block.timestamp) + _maxPauseDuration();
        if (until > maxUntil) revert PauseDurationTooLong(scope, until, maxUntil);
        _pauses[scope] = PauseEntry({ until: until, reasonRef: reasonRef });
        emit PauseSet(scope, until, reasonRef, _pauseAuthorityMode(scope));

        PdaRecord storage record = _records[scope];
        if (record.registered && record.lifecycle != LifecycleState.Paused) {
            record.pausedBaseState = record.lifecycle;
            _transition(scope, record, LifecycleState.Paused);
        }
    }

    function unpause(bytes32 scope) external override {
        _authorizePause(scope, msg.sender);
        delete _pauses[scope];
        emit PauseCleared(scope);

        PdaRecord storage record = _records[scope];
        if (record.registered && record.lifecycle == LifecycleState.Paused) {
            LifecycleState restore = record.pausedBaseState == LifecycleState.Unregistered
                ? LifecycleState.Registered
                : record.pausedBaseState;
            _transition(scope, record, restore);
            record.pausedBaseState = LifecycleState.Unregistered;
        }
    }

    function _validateRegistration(bytes32 authorizationId, PDARegistration calldata registration) private pure {
        if (registration.hCommitFields.commitVersion != ProtocolVersion.BUILD_PROTOCOL_VERSION) {
            revert BuildProtocolVersionMismatch(
                registration.hCommitFields.commitVersion, ProtocolVersion.BUILD_PROTOCOL_VERSION
            );
        }
        _requireValidAxisMode(registration.revealAxis.mode);
        _requireValidAxisMode(registration.shredAxis.mode);
        if (registration.pdaRootFields.revealConditionMode != uint8(registration.revealAxis.mode)) {
            revert ConditionInvalidMode(registration.pdaRootFields.revealConditionMode);
        }
        if (registration.pdaRootFields.shredConditionMode != uint8(registration.shredAxis.mode)) {
            revert ConditionInvalidMode(registration.pdaRootFields.shredConditionMode);
        }
        if (registration.revealAxis.challengeWindow != registration.hCommitFields.revealChallengeWindow) {
            revert ConditionInvalidMode(uint8(registration.revealAxis.challengeWindow));
        }
        if (registration.shredAxis.challengeWindow != registration.hCommitFields.shredChallengeWindow) {
            revert ConditionInvalidMode(uint8(registration.shredAxis.challengeWindow));
        }

        bool legalEffect = registration.legalFlags.legalEffectExpected || registration.pdaRootFields.legalEffectExpected;
        bool haltOptOut =
            registration.legalFlags.cealisClassWideHaltOptOut || registration.pdaRootFields.cealisClassWideHaltOptOut;
        if (legalEffect && registration.legalFlags.requiredG4Phase == G4Phase.Phase1) {
            revert ConditionLegalEffectPhaseInvalid(authorizationId, uint8(G4Phase.Phase1));
        }
        if (legalEffect && haltOptOut) revert ConditionLegalEffectHaltOptOutForbidden(authorizationId);
        if (
            legalEffect
                && (registration.legalFlags.subjectAuthenticatorClass == SYNCED_PASSKEY_CLASS
                    || registration.pdaRootFields.subjectAuthenticatorClass == SYNCED_PASSKEY_CLASS)
        ) {
            revert LegalEffectSyncedPasskeyForbidden(authorizationId);
        }
        if (registration.legalFlags.qesRequired && registration.pdaRootFields.qtspProviderRef == bytes32(0)) {
            revert ConditionQesQtspMissing(authorizationId);
        }
        if (
            (registration.legalFlags.art9Scoped || registration.pdaRootFields.art9Scoped)
                && (registration.legalFlags.art9BasisId == 0 && registration.pdaRootFields.art9BasisId == 0)
        ) {
            revert ConditionArt9BasisMissing(authorizationId);
        }
        if (!registration.shredGuardrailCompiled) revert ConditionShredGuardrailMissing(authorizationId);
        // BR-D: a non-Disabled shred-authority PDA must carry a minimum shred
        // latency AND a minimum shred challenge window. Forecloses a compromised
        // ORCHESTRATOR registering hostile PDAs with latency=0 + window=0 for an
        // immediate, unchallengeable shred. Disabled-shred PDAs (permanent
        // archival / testament / evidence) are exempt — there is no shred path.
        ShredAuthorityMode shredAuthority = _decodeShredAuthority(registration.hCommitFields.shredAuthorityId);
        if (shredAuthority != ShredAuthorityMode.Disabled && shredAuthority != ShredAuthorityMode.None) {
            if (registration.pdaRootFields.minimumShredLatency < MIN_SHRED_LATENCY_FLOOR) {
                revert ConditionShredLatencyBelowFloor(
                    authorizationId, registration.pdaRootFields.minimumShredLatency, MIN_SHRED_LATENCY_FLOOR
                );
            }
            if (registration.shredAxis.challengeWindow < MIN_SHRED_CHALLENGE_WINDOW) {
                revert ConditionShredLatencyBelowFloor(
                    authorizationId, registration.shredAxis.challengeWindow, MIN_SHRED_CHALLENGE_WINDOW
                );
            }
        }
        if (uint8(registration.pauseAuthorityMode) > uint8(PauseAuthorityMode.None)) {
            revert ConditionPauseAuthorityInvalid(uint8(registration.pauseAuthorityMode));
        }
        for (uint256 i = 0; i < registration.conditionalRecipientModes.length; ++i) {
            if (registration.conditionalRecipientModes[i] == ConditionalRecipientMode.WalletEIP1271Reserved) {
                revert ConditionMode3Reserved(authorizationId);
            }
        }
    }

    function _evaluateAxis(bytes32 authorizationId, CeremonyAxis axis, AxisConfig memory config, bytes32 evidenceRef)
        private
        returns (bytes32 conditionRef)
    {
        if (config.mode == ConditionMode.ModeF) {
            // F-1: do NOT fabricate a 0→1 terminal transition. Mode-F state is
            // advanced only through the dedicated `advanceFSM` entry point, which
            // carries the real submitter-supplied transitionProof and validates
            // each edge against the fsmHash-committed transition set. Here we read
            // the FSM's ACTUAL terminal status; if it has not been driven to its
            // committed terminal state through validated edges, the condition is
            // not met and authorization reverts.
            if (!IFSMTerminalView(address(_fsmInterpreter)).isTerminal(authorizationId, axis)) {
                revert ConditionNotMet(authorizationId, axis);
            }
            return config.conditionRef;
        }

        address module = _addressFromRef(config.conditionSpecHash);
        if (module != address(0) && module.code.length != 0) {
            // B3b: conditionSpecHash is supplied by ORCHESTRATOR at registerPDA and
            // is otherwise an arbitrary address. Before dispatching evaluate(), assert
            // the target is one of the engine-governed _conditionModules — otherwise a
            // registration could point the predicate at an attacker-controlled contract
            // whose evaluate() returns true (authorization bypass).
            if (!_isRegisteredModule(module)) revert ConditionNotMet(authorizationId, axis);
            if (!IConditionModule(module).evaluate(authorizationId, evidenceRef)) {
                revert ConditionNotMet(authorizationId, axis);
            }
            return config.conditionRef;
        }
        if (address(_claimDSL) == address(0)) revert ConditionNotMet(authorizationId, axis);
        if (!_claimDSL.evaluateClaim(
                _records[authorizationId].registryRefs.dslVersionRef, config.conditionRef, evidenceRef
            )) {
            revert ConditionNotMet(authorizationId, axis);
        }
        return config.conditionRef;
    }

    function _requireRevealPreconditions(bytes32 authorizationId, PdaRecord storage record) private view {
        _requireNotPaused(authorizationId);
        bool revealAttemptAllowed = record.lifecycle == LifecycleState.Registered
            || record.lifecycle == LifecycleState.ShredConditionMet
            || record.lifecycle == LifecycleState.ShredChallengeOpen;
        if (!revealAttemptAllowed) {
            if (record.lifecycle == LifecycleState.Shredded) revert ConditionShredded(record.hCommit);
            revert ConditionChallengeWindowActive(authorizationId, CeremonyAxis.Reveal);
        }
        if (_isShreddedView(record.hCommit)) revert ConditionShredded(record.hCommit);
        _touchRegistryRefs(record.registryRefs, record.registrationBlock);
        _requireNoBlockingRefusal(authorizationId);
    }

    function _requireShredPreconditions(bytes32 authorizationId, PdaRecord storage record) private view {
        _requireNotPaused(authorizationId);
        if (record.lifecycle != LifecycleState.Registered && record.lifecycle != LifecycleState.RevealChallengeOpen) {
            revert ConditionChallengeWindowActive(authorizationId, CeremonyAxis.Shred);
        }
        if (record.postChallengeReveal || record.lifecycle == LifecycleState.PostChallengeRevealInProgress) {
            revert ConditionChallengeWindowActive(authorizationId, CeremonyAxis.Shred);
        }
        if (_isShreddedView(record.hCommit)) revert ConditionShredded(record.hCommit);
        _touchRegistryRefs(record.registryRefs, record.registrationBlock);
        _requireNoBlockingRefusal(authorizationId);
    }

    function _requireAuthorization(bytes32 authorizationId) private view returns (PdaRecord storage record) {
        record = _records[authorizationId];
        if (!record.registered) revert ConditionUnknownAuthorization(authorizationId);
    }

    function _requireNotPaused(bytes32 authorizationId) private view {
        if (_isPausedView(GLOBAL_SCOPE) || _isPausedView(authorizationId)) revert ConditionPaused(authorizationId);
    }

    function _requireNoBlockingRefusal(bytes32 authorizationId) private view {
        if (_g4RefusalRegistry == address(0)) return;
        // slither-disable-next-line unused-return -- the two used return values (refused, reasonCode) are consumed below; the trailing tuple member is deliberately unnamed and unused
        try IG4RefusalRegistryD2(_g4RefusalRegistry).refusalState(authorizationId) returns (
            bool refused, uint8 reasonCode, bool
        ) {
            if (refused) revert ConditionG4Refused(authorizationId, reasonCode);
        } catch { }
    }

    function _hasBlockingRefusal(bytes32 authorizationId) private view returns (bool) {
        if (_g4RefusalRegistry == address(0)) return false;
        // slither-disable-next-line unused-return -- only `refused` is needed here; the other two tuple members are deliberately unnamed and unused
        try IG4RefusalRegistryD2(_g4RefusalRegistry).refusalState(authorizationId) returns (bool refused, uint8, bool) {
            return refused;
        } catch {
            return false;
        }
    }

    function _isShreddedView(bytes32 hCommit) private view returns (bool) {
        if (_shredRegistry == address(0)) return false;
        try IShredRegistryD2(_shredRegistry).isShredded(hCommit) returns (bool shredded) {
            return shredded;
        } catch {
            return false;
        }
    }

    function _isPausedView(bytes32 scope) private view returns (bool) {
        PauseEntry memory entry = _pauses[scope];
        return entry.until != 0 && block.timestamp < entry.until;
    }

    /// @dev BR-H: probe registry validity at the PDA's authorization (registration)
    ///      block, NOT the current block. A registry entry tombstoned AFTER
    ///      authorization but before reveal must not retroactively break an
    ///      in-flight ceremony (S2-2 §1080: "a tombstone after authorization does
    ///      not retroactively break an in-flight ceremony"; §1115: read at
    ///      authorization block, never the mutable current schema view).
    function _touchRegistryRefs(RegistryRefs memory refs, uint64 targetBlock) private view {
        _registryReadAt(_pluginHashRegistry, refs.pluginVersionDigest, targetBlock);
        _registryReadAt(_g4AuthorityRegistry, refs.g4AuthorityRef, targetBlock);
        _registryReadAt(_dslVersionRegistry, refs.dslVersionRef, targetBlock);
        _registryReadAt(_qtspRegistry, refs.qtspProviderRef, targetBlock);
    }

    function _registryReadAt(address registry, bytes32 id, uint64 targetBlock) private view {
        if (registry == address(0) || id == bytes32(0)) return;
        // slither-disable-next-line unused-return -- intentional at-commit-block validity probe: getEntryAt reverts on missing / not-yet-effective / tombstoned entry; the returned struct is not needed, only the revert-or-not behavior. (Deprecated-but-not-tombstoned entries return normally by design — deprecation is enforced off-chain by G4 via refusalState, per S2-2 smart-contracts-spec §line 1211. Verified by solidity-auditor 2026-05-16.)
        IBaseRegistry(registry).getEntryAt(id, targetBlock);
    }

    function _transition(bytes32 authorizationId, PdaRecord storage record, LifecycleState newState) private {
        LifecycleState oldState = record.lifecycle;
        if (oldState == newState) return;
        record.lifecycle = newState;
        emit LifecycleStateChanged(authorizationId, oldState, newState);
    }

    function _requireValidAxisMode(ConditionMode mode) private pure {
        if (mode != ConditionMode.ModeF && mode != ConditionMode.ModeP) {
            revert ConditionInvalidMode(uint8(mode));
        }
    }

    function _decodeShredAuthority(bytes32 authorityId) private pure returns (ShredAuthorityMode) {
        uint256 raw = uint256(authorityId);
        if (raw == 1) return ShredAuthorityMode.Subject;
        if (raw == 2) return ShredAuthorityMode.Joint;
        if (raw == 3) return ShredAuthorityMode.Operator;
        if (raw == 4) return ShredAuthorityMode.Timelock;
        if (raw == 5) return ShredAuthorityMode.Disabled;
        return ShredAuthorityMode.None;
    }

    function _addressFromRef(bytes32 ref) private pure returns (address) {
        return address(uint160(uint256(ref)));
    }

    /// @dev B3b: membership check against the engine-governed module set wired at
    ///      initialize() (and only changeable via UUPS upgrade by the timelock).
    function _isRegisteredModule(address module) private view returns (bool) {
        for (uint256 i = 0; i < _conditionModules.length; ++i) {
            if (_conditionModules[i] == module) return true;
        }
        return false;
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (!hasRole(Roles.PAUSER_ROLE, caller)) revert PauseUnauthorized(scope, caller);
    }

    function _maxPauseDuration() internal pure override returns (uint64) {
        return PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
    }

    function _pauseAuthorityMode(bytes32 scope) internal view override returns (PauseAuthorityMode) {
        PdaRecord memory record = _records[scope];
        return record.registered ? record.pauseAuthorityMode : PauseAuthorityMode.Joint;
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }

    uint256[50] private __gap;
}
