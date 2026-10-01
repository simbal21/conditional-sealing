// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { IHeartbeatMissedModule } from "../engine/IConditionEngine.sol";
import { ConditionModuleBase } from "./PaymentObligationModule.sol";

/// @title HeartbeatMissedModule - missed-liveness reveal condition
/// @notice One of the 9 ConditionEngine modules. Predicate fires when an actor
///         (subject, oracle, governance signer, or off-chain process) fails to
///         post a heartbeat before its rolling deadline. Drives use cases:
///         operator-incapacitation cutover, oracle-liveness fallback,
///         escrow-agent step-out, multi-party governance fail-safe,
///         long-running service-level-agreement enforcement.
/// @dev Distinct from DeadManSwitchModule: heartbeat-missed is a HARD-DEADLINE
///      process-liveness primitive (interval + gracePeriod tight), suited to
///      machine/service monitors. DeadManSwitch has a soft gracePeriod and
///      human-cadence semantics (testament, journalism). Default fallback
///      (interval=1 days, gracePeriod=1 hours) applies when configured via
///      empty `config` bytes — chosen for typical operator-liveness use.
/// @dev SC-F-06: a heartbeat AUTHENTICATES proof-of-life. It slides the deadline
///      FORWARD, so a forged heartbeat does not directly trigger a reveal — it
///      *suppresses* a legitimate one (the testator/journalist is kept "alive"
///      indefinitely and the dead-man release never fires). The trigger itself
///      (deadline lapse) is unforgeable, but the heartbeat is an on-chain
///      authentication event whose forgeability would defeat the whole liveness
///      guarantee. S2-2 §718 invariant: "Heartbeat signer must match the
///      PDA-bound actor." Therefore on-chain recovery IS required: each
///      heartbeat carries an EIP-712 typed-data signature (`CealisHeartbeat`
///      domain, S2-2 §1.6 / §15.1) inside `signatureEnvelopeRef`, ABI-encoded as
///      `(address actor, bytes signature)`. The module recovers the signer and
///      rejects unless it equals the claimed actor AND that actor is the
///      PDA-bound `actorRef`. The domain separator mixes `block.chainid` +
///      `address(this)` → cross-chain / cross-contract replay rejected
///      (S2-2 §15.2). actorRef stays fully PDA-configurable — nothing hardcoded.
contract HeartbeatMissedModule is ConditionModuleBase, IHeartbeatMissedModule {
    struct HeartbeatState {
        bytes32 actorRef;
        uint64 interval;
        uint64 gracePeriod;
        uint64 lastHeartbeat;
        uint64 deadline;
        bool missed;
    }

    /// @dev EIP-712 domain (S2-2 §1.6 / §15.1): name `CealisHeartbeat`, version `1`.
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisHeartbeat");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    /// @dev `Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)`.
    bytes32 private constant _HEARTBEAT_TYPEHASH =
        keccak256("Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)");

    mapping(bytes32 => HeartbeatState) private _heartbeats;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
    }

    /// @notice Configures the heartbeat-missed condition for an authorizationId.
    /// @dev Access: onlyConditionEngineOrModuleAdmin. actorRef binds the expected
    ///      heartbeat signer/sender (cross-ref'd in _recordHeartbeat by envelope
    ///      ref). Initial state: lastHeartbeat = now, deadline = now + interval
    ///      + gracePeriod, missed = false. NO zero-validation on interval or
    ///      gracePeriod at this entry — note the internal _configureModule path
    ///      DOES enforce non-zero; configureHeartbeat is the direct CE/admin
    ///      path and admin is expected to set sensible values per use case.
    function configureHeartbeat(
        bytes32 authorizationId,
        bytes32 actorRef,
        uint64 interval,
        uint64 gracePeriod,
        bytes32 configDigest
    ) external onlyConditionEngineOrModuleAdmin {
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: actorRef, configDigest: configDigest });
        _heartbeats[authorizationId] = HeartbeatState({
            actorRef: actorRef,
            interval: interval,
            gracePeriod: gracePeriod,
            lastHeartbeat: uint64(block.timestamp),
            deadline: uint64(block.timestamp + interval + gracePeriod),
            missed: false
        });
        emit ModuleConfigured(authorizationId, actorRef, configDigest);
    }

    /// @notice Records a subject heartbeat, sliding the missed-heartbeat deadline forward.
    /// @dev Contract-only (onlyConditionEngine). Used by dead-man-switch flows (S2-6
    ///      DeadManSwitchPDA archetype): subject must heartbeat before deadline to
    ///      prevent the predicate from evaluating true. Each heartbeat resets the
    ///      deadline by the configured interval. After deadline lapses, the predicate
    ///      fires and the reveal/shred can be authorized.
    /// @param authorizationId target PDA authorization.
    /// @param heartbeatDigest hash of the subject's heartbeat evidence.
    /// @param signatureEnvelopeRef ABI-encoded `(address actor, bytes signature)`; the
    ///        EIP-712 `Heartbeat` signature must recover to `actor` and `actor` must be
    ///        the PDA-bound `actorRef` (SC-F-06, S2-2 §718).
    function recordHeartbeat(bytes32 authorizationId, bytes32 heartbeatDigest, bytes calldata signatureEnvelopeRef)
        external
        onlyConditionEngine
    {
        _recordHeartbeat(authorizationId, heartbeatDigest, signatureEnvelopeRef);
    }

    /// @notice Returns the absolute deadline timestamp after which the heartbeat is considered missed.
    /// @dev View. Reverts if authorizationId is unknown. deadline = lastHeartbeat +
    ///      interval + gracePeriod. block.timestamp > deadline means predicate fires.
    function heartbeatDeadline(bytes32 authorizationId) external view returns (uint64) {
        _requireKnown(authorizationId);
        return _heartbeats[authorizationId].deadline;
    }

    /// @notice Returns the full heartbeat state for monitoring/dashboard use.
    /// @dev View. Reverts if unknown. Used by liveness-monitoring services and
    ///      operator dashboards to display remaining-time + missed-flag.
    function heartbeatState(bytes32 authorizationId) external view returns (HeartbeatState memory) {
        _requireKnown(authorizationId);
        return _heartbeats[authorizationId];
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32 configDigest)
        internal
        override
    {
        uint64 interval = 1 days;
        uint64 gracePeriod = 1 hours;
        if (config.length != 0) {
            (interval, gracePeriod) = abi.decode(config, (uint64, uint64));
        }
        if (interval == 0 || gracePeriod == 0) revert ModuleInvalidEvidence(configDigest);
        _heartbeats[authorizationId] = HeartbeatState({
            actorRef: moduleRef,
            interval: interval,
            gracePeriod: gracePeriod,
            lastHeartbeat: uint64(block.timestamp),
            deadline: uint64(block.timestamp + interval + gracePeriod),
            missed: false
        });
    }

    function _advanceModule(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        internal
        override
        returns (bool)
    {
        if (proof.length != 0) {
            _recordHeartbeat(authorizationId, evidenceRef, proof);
            return false;
        }
        HeartbeatState storage state = _heartbeats[authorizationId];
        if (block.timestamp <= state.deadline) revert HeartbeatNotMissed(authorizationId, state.deadline);
        state.missed = true;
        emit HeartbeatMissed(authorizationId, state.actorRef, uint64(block.timestamp));
        return true;
    }

    function _evaluateModule(bytes32 authorizationId, bytes32) internal view override returns (bool) {
        HeartbeatState memory state = _heartbeats[authorizationId];
        return state.missed || block.timestamp > state.deadline;
    }

    function _recordHeartbeat(bytes32 authorizationId, bytes32 heartbeatDigest, bytes calldata signatureEnvelopeRef)
        private
    {
        _requireKnown(authorizationId);
        _requireNotPaused(authorizationId);
        HeartbeatState storage state = _heartbeats[authorizationId];
        if (state.missed) revert HeartbeatNotMissed(authorizationId, state.deadline);
        if (signatureEnvelopeRef.length == 0 || heartbeatDigest == bytes32(0)) {
            revert HeartbeatInvalidActor(authorizationId, msg.sender);
        }
        // SC-F-06 (S2-2 §718): authenticate proof-of-life. The envelope is
        // `(address actor, bytes signature)`; recover the EIP-712 `Heartbeat` signer and
        // require it to equal the claimed actor AND the PDA-bound actorRef. Without this,
        // any non-empty envelope slides the deadline forward and a third party could keep
        // the dead-man release suppressed forever. The PDA-bound actor stays configurable
        // (actorRef) — nothing hardcoded. tryRecover (not recover) fails closed to
        // address(0) on malformed bytes, surfacing this module's own actor error.
        (address actor, bytes memory signature) = abi.decode(signatureEnvelopeRef, (address, bytes));
        if (bytes32(uint256(uint160(actor))) != state.actorRef) {
            revert HeartbeatInvalidActor(authorizationId, actor);
        }
        bytes32 digest = _heartbeatTypedDataHash(authorizationId, heartbeatDigest, actor);
        (address recovered,,) = ECDSA.tryRecover(digest, signature);
        if (recovered != actor) {
            revert HeartbeatInvalidActor(authorizationId, actor);
        }
        state.lastHeartbeat = uint64(block.timestamp);
        state.deadline = uint64(block.timestamp + state.interval + state.gracePeriod);
        emit HeartbeatRecorded(authorizationId, state.actorRef, state.deadline);
    }

    /// @dev EIP-712 digest over the `Heartbeat` struct. Self-contained (no shared lib) so this
    ///      module owns its `CealisHeartbeat` domain. Domain separator binds `block.chainid`
    ///      + `address(this)` → cross-chain / cross-contract replay rejected (S2-2 §15.2).
    function _heartbeatTypedDataHash(bytes32 authorizationId, bytes32 heartbeatDigest, address actor)
        private
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid, address(this)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_HEARTBEAT_TYPEHASH, authorizationId, heartbeatDigest, actor));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    uint256[50] private __gap;
}
