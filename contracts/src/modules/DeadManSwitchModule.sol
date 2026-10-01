// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { IDeadManSwitchModule } from "../engine/IConditionEngine.sol";
import { ConditionModuleBase } from "./PaymentObligationModule.sol";

/// @title DeadManSwitchModule - condition module for inactivity-triggered reveal
/// @notice One of the 9 ConditionEngine modules. Predicate fires when the subject
///         fails to send a "still alive" heartbeat before (interval + gracePeriod)
///         elapses. Drives use cases: testament/inheritance reveal, journalist
///         dead-man's switch (auto-release of source-protection material to
///         designated recipients on death/disappearance), founder-incapacitation
///         escalation, long-running custody escalation.
/// @dev Distinct from HeartbeatMissedModule: dead-man has a soft `gracePeriod`
///      AFTER the interval — designed for human cadences (illness, travel,
///      forgotten-but-not-dead). Heartbeat-missed is hard-deadline for
///      machine/process liveness. Recipient policy is bound to
///      recipientPolicyDigest at configure time; the reveal artifact bundle
///      resolves recipients via PDA's conditional_recipient stanza.
/// @dev SC-F-06: the heartbeat AUTHENTICATES proof-of-life. It slides the deadline
///      FORWARD, so a forged heartbeat does not directly trigger a reveal — it
///      *suppresses* a legitimate one (a journalist's source-protection material
///      never auto-releases because an attacker keeps forging "still alive"
///      heartbeats after the journalist is dead/disappeared). The trigger itself
///      (deadline lapse) is time-based and unforgeable, but the heartbeat is an
///      on-chain authentication event whose forgeability defeats the entire
///      dead-man guarantee. DeadManSwitch composes HeartbeatMissed (S2-2 §4.9), so
///      the S2-2 §718 invariant "Heartbeat signer must match the PDA-bound actor"
///      applies. Therefore on-chain recovery IS required: each heartbeat carries an
///      EIP-712 `CealisDeadManSwitch` typed-data signature inside
///      `signatureEnvelopeRef`, ABI-encoded as `(address actor, bytes signature)`.
///      The module recovers the signer and rejects unless it equals the claimed
///      actor AND the PDA-bound `actor`. The domain separator mixes `block.chainid`
///      + `address(this)` → cross-chain / cross-contract replay rejected
///      (S2-2 §15.2). The subject `actor` is PDA-configurable — nothing hardcoded.
contract DeadManSwitchModule is ConditionModuleBase, IDeadManSwitchModule {
    struct DeadManState {
        bytes32 recipientPolicyDigest;
        address actor;
        uint64 interval;
        uint64 gracePeriod;
        uint64 lastHeartbeat;
        uint64 deadline;
        bool triggered;
    }

    /// @dev EIP-712 domain (S2-2 §1.6 / §15.1): name `CealisDeadManSwitch`, version `1`.
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisDeadManSwitch");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    /// @dev `Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)`.
    bytes32 private constant _HEARTBEAT_TYPEHASH =
        keccak256("Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)");

    mapping(bytes32 => DeadManState) private _states;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
    }

    /// @notice Configures the dead-man condition for an authorizationId.
    /// @dev Access: onlyConditionEngineOrModuleAdmin. Initial state: lastHeartbeat
    ///      = now, deadline = now + interval + gracePeriod, triggered = false.
    ///      recipientPolicyDigest binds the off-chain recipient set (resolved at
    ///      reveal via PDA conditional_recipient policy). Overwrites any prior
    ///      config — testators may re-configure as life circumstances change.
    /// @param actor PDA-bound subject whose EIP-712 `Heartbeat` signature is the only
    ///        accepted proof-of-life (SC-F-06). Fully PDA-configurable — nothing hardcoded.
    function configureDeadManSwitch(
        bytes32 authorizationId,
        bytes32 recipientPolicyDigest,
        address actor,
        uint64 interval,
        uint64 gracePeriod,
        bytes32 configDigest
    ) external onlyConditionEngineOrModuleAdmin {
        _moduleConfigs[authorizationId] = ModuleConfig({
            configured: true, moduleRef: recipientPolicyDigest, configDigest: configDigest
        });
        _states[authorizationId] = DeadManState({
            recipientPolicyDigest: recipientPolicyDigest,
            actor: actor,
            interval: interval,
            gracePeriod: gracePeriod,
            lastHeartbeat: uint64(block.timestamp),
            deadline: uint64(block.timestamp + interval + gracePeriod),
            triggered: false
        });
        emit ModuleConfigured(authorizationId, recipientPolicyDigest, configDigest);
    }

    /// @notice Records a "still alive" subject heartbeat, sliding the dead-man deadline.
    /// @dev Contract-only (onlyConditionEngine). Each heartbeat sets
    ///      lastHeartbeat = block.timestamp and deadline = block.timestamp + interval
    ///      + gracePeriod. The predicate evaluates true after deadline lapses without
    ///      a new heartbeat. Distinguishes from HeartbeatMissedModule by including
    ///      gracePeriod for soft-deadline reveal-trigger semantics.
    /// @param signatureEnvelopeRef ABI-encoded `(address actor, bytes signature)`; the
    ///        EIP-712 `Heartbeat` signature must recover to `actor` and `actor` must be
    ///        the PDA-bound subject (SC-F-06). A forged ref cannot suppress the release.
    function recordDeadManHeartbeat(
        bytes32 authorizationId,
        bytes32 heartbeatDigest,
        bytes calldata signatureEnvelopeRef
    ) external onlyConditionEngine {
        _record(authorizationId, heartbeatDigest, signatureEnvelopeRef);
    }

    /// @notice Returns the absolute deadline timestamp after which the predicate fires.
    /// @dev View. Reverts if authorizationId is unknown. deadline = lastHeartbeat +
    ///      interval + gracePeriod. Compare to block.timestamp: if block.timestamp >
    ///      deadline, the dead-man condition has expired and reveal is authorizable.
    function deadManDeadline(bytes32 authorizationId) external view returns (uint64) {
        _requireKnown(authorizationId);
        return _states[authorizationId].deadline;
    }

    /// @notice Returns the full dead-man state for an authorizationId.
    /// @dev View. Reverts if unknown. Used by indexers + recipient UIs to display
    ///      remaining-time + heartbeat-history + triggered-flag to subject/recipients.
    function deadManState(bytes32 authorizationId) external view returns (DeadManState memory) {
        _requireKnown(authorizationId);
        return _states[authorizationId];
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32)
        internal
        override
    {
        // PDA-driven config: `(address actor, uint64 interval, uint64 gracePeriod)`. The actor
        // is the PDA-bound subject whose EIP-712 heartbeat is the only accepted proof-of-life
        // (SC-F-06). Fully PDA-configurable — nothing hardcoded.
        (address actor, uint64 interval, uint64 gracePeriod) = abi.decode(config, (address, uint64, uint64));
        _states[authorizationId] = DeadManState({
            recipientPolicyDigest: moduleRef,
            actor: actor,
            interval: interval,
            gracePeriod: gracePeriod,
            lastHeartbeat: uint64(block.timestamp),
            deadline: uint64(block.timestamp + interval + gracePeriod),
            triggered: false
        });
    }

    function _advanceModule(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        internal
        override
        returns (bool)
    {
        if (proof.length != 0) {
            _record(authorizationId, evidenceRef, proof);
            return false;
        }
        DeadManState storage state = _states[authorizationId];
        if (block.timestamp <= state.deadline) revert DeadManSwitchGraceActive(authorizationId, state.deadline);
        state.triggered = true;
        emit DeadManSwitchTriggered(authorizationId, state.recipientPolicyDigest);
        return true;
    }

    function _evaluateModule(bytes32 authorizationId, bytes32) internal view override returns (bool) {
        DeadManState memory state = _states[authorizationId];
        return state.triggered || block.timestamp > state.deadline;
    }

    function _record(bytes32 authorizationId, bytes32 heartbeatDigest, bytes calldata signatureEnvelopeRef) private {
        _requireKnown(authorizationId);
        _requireNotPaused(authorizationId);
        if (signatureEnvelopeRef.length == 0 || heartbeatDigest == bytes32(0)) {
            revert DeadManSwitchRecipientPolicyMismatch(authorizationId);
        }
        DeadManState storage state = _states[authorizationId];
        if (state.triggered) revert DeadManSwitchGraceActive(authorizationId, state.deadline);
        // SC-F-06 (S2-2 §4.9 / §718): authenticate proof-of-life. The envelope is
        // `(address actor, bytes signature)`; recover the EIP-712 `Heartbeat` signer and
        // require it to equal the claimed actor AND the PDA-bound subject. Without this, any
        // non-empty envelope slides the deadline forward — a third party could keep a dead
        // testator/journalist "alive" forever and suppress the inheritance / source release.
        // tryRecover (not recover) fails closed to address(0) on malformed bytes, surfacing
        // this module's own mismatch error rather than an OZ revert. The interface exposes
        // only DeadManSwitch{GraceActive,RecipientPolicyMismatch}, so authentication failures
        // reuse RecipientPolicyMismatch (the heartbeat does not satisfy the bound policy).
        (address actor, bytes memory signature) = abi.decode(signatureEnvelopeRef, (address, bytes));
        if (actor != state.actor) revert DeadManSwitchRecipientPolicyMismatch(authorizationId);
        bytes32 digest = _heartbeatTypedDataHash(authorizationId, heartbeatDigest, actor);
        (address recovered,,) = ECDSA.tryRecover(digest, signature);
        if (recovered != actor) revert DeadManSwitchRecipientPolicyMismatch(authorizationId);
        state.lastHeartbeat = uint64(block.timestamp);
        state.deadline = uint64(block.timestamp + state.interval + state.gracePeriod);
    }

    /// @dev EIP-712 digest over the `Heartbeat` struct. Self-contained (no shared lib) so this
    ///      module owns its `CealisDeadManSwitch` domain. Domain separator binds `block.chainid`
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
