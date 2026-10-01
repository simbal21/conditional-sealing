// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { IFSMInterpreter } from "../engine/IConditionEngine.sol";
import { CeremonyAxis, PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";
import { FSMAdvanceResult } from "../lib/Structs.sol";

/// @title FSMInterpreter - PDA finite-state-machine reveal/shred condition driver
/// @notice Drives PDA-defined finite state machines for both reveal and shred
///         ceremonies (Mode F per S2-2 §4). Each (authorizationId, CeremonyAxis)
///         tuple has its own independent FSM state. Use cases: KYC re-onboarding
///         sequences with prescribed state order (Identity verified →
///         Risk-score acquired → Source-of-funds checked → Final approval), M&A
///         deal-stage progression, multi-phase regulatory reveal protocols.
/// @dev Bounded execution: maxTransitions caps total state advances (DoS bound;
///      coerced to 1 if 0 passed). deadline caps the wall-clock window.
///      cursorData accumulates as keccak(prev || transitionId || attestationDigest)
///      across calls — tamper-evident lineage that auditors can reconstruct
///      from event log + cursorData chain. Only ConditionEngine may advance
///      (advanceFSM is contract-callable, not user-callable). Two-axis storage
///      keeps reveal and shred FSMs strictly independent for the same
///      authorizationId.
contract FSMInterpreter is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable, IFSMInterpreter {
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    /// @dev Domain-separation label for FSM transition-edge merkle leaves.
    ///      Local to this interpreter (not a global TAG_*_V3) so the
    ///      edge-membership construction stays self-contained; the canonical
    ///      cross-stack TAG registration is design-sensitive and tracked for
    ///      Simon's ratification in S2-2 §6 (F-1 fix). Refer-by-class only.
    bytes32 private constant TAG_FSM_EDGE = keccak256("CEALIS_V3_FSM_TRANSITION_EDGE_V3");

    struct FSMState {
        uint32 currentState;
        uint32 terminalState;
        uint64 lastAdvancedAt;
        uint64 deadline;
        bytes32 fsmHash;
        bytes32 cursorData;
        uint32 transitionCount;
        uint32 maxTransitions;
        bool configured;
        // F-1: merkle root over the legal transition-edge set bound by fsmHash.
        // Every advanceFSM edge must prove membership under this root. Append-only.
        bytes32 edgeRoot;
    }

    struct TransitionProof {
        bytes32 fsmHash;
        uint32 fromState;
        uint32 toState;
        uint32 terminalState;
        uint32 maxTransitions;
        address allowedSubmitter;
        bytes32 conditionRef;
        uint64 deadline;
        // F-1: merkle proof that leaf(fromState,toState,transitionId) is a member
        // of the committed edge set (edgeRoot). Empty proof is only valid when the
        // leaf itself IS the root (single-edge FSM).
        bytes32[] edgeProof;
    }

    address private _conditionEngine;
    mapping(bytes32 => mapping(CeremonyAxis => FSMState)) private _states;

    event FSMConfigured(
        bytes32 indexed authorizationId,
        CeremonyAxis indexed axis,
        bytes32 fsmHash,
        uint32 initialState,
        uint32 terminalState
    );

    error FSMPaused(bytes32 scope);
    /// @notice F-1: the submitted (fromState,toState,transitionId) edge is not a
    ///         member of the fsmHash-committed transition set (edgeRoot).
    error FSMEdgeNotInCommittedSet(bytes32 authorizationId, uint32 fromState, uint32 toState, bytes32 transitionId);

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine_) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
        _grantRole(Roles.MODULE_ADMIN_ROLE, timelock);
        _conditionEngine = conditionEngine_;
    }

    /// @notice Configures the FSM for a given (authorizationId, CeremonyAxis) pair.
    /// @dev MODULE_ADMIN_ROLE only. fsmHash binds the off-chain canonical FSM
    ///      bytecode (transition table). initialState + terminalState define
    ///      entry + accept. maxTransitions=0 is coerced to 1 (single-shot).
    ///      deadline=0 means no wall-clock bound. cursorData seeds the
    ///      tamper-evident lineage — typically empty bytes32(0) but can
    ///      contain a deployment-pinned IV for cross-deployment uniqueness.
    ///      Overwrites any prior config; should NOT be called once the FSM
    ///      has begun advancing.
    function configureFSM(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 fsmHash,
        uint32 initialState,
        uint32 terminalState,
        uint32 maxTransitions,
        uint64 deadline,
        bytes32 cursorData
    ) external onlyRole(Roles.MODULE_ADMIN_ROLE) {
        _states[authorizationId][axis] = FSMState({
            currentState: initialState,
            terminalState: terminalState,
            lastAdvancedAt: 0,
            deadline: deadline,
            fsmHash: fsmHash,
            cursorData: cursorData,
            transitionCount: 0,
            maxTransitions: maxTransitions == 0 ? 1 : maxTransitions,
            configured: true,
            // F-1: clean overwrite resets the edge set. The legal transition set
            // must be (re-)bound via configureFSMEdges; until then advanceFSM
            // fails closed (no edge can prove membership against a zero root).
            edgeRoot: bytes32(0)
        });
        emit FSMConfigured(authorizationId, axis, fsmHash, initialState, terminalState);
    }

    /// @notice Binds the legal transition-edge set for a configured FSM (F-1).
    /// @dev MODULE_ADMIN_ROLE only. `edgeRoot` is the merkle root over the
    ///      canonical edge leaves `keccak256(TAG_FSM_EDGE ‖ fsmHash ‖ fromState
    ///      ‖ toState ‖ transitionId)`. For a single-edge FSM, `edgeRoot` IS
    ///      that one leaf and advanceFSM is called with an empty edgeProof.
    ///      Must be set after configureFSM (which zeroes it) and before any
    ///      advance: a zero root rejects every transition (fail-closed).
    ///      `edgeRoot == bytes32(0)` is rejected to prevent re-introducing the
    ///      fail-open hole.
    /// @param authorizationId target PDA authorization.
    /// @param axis CeremonyAxis.Reveal or CeremonyAxis.Shred.
    /// @param edgeRoot merkle root binding the legal transition edges.
    function configureFSMEdges(bytes32 authorizationId, CeremonyAxis axis, bytes32 edgeRoot)
        external
        onlyRole(Roles.MODULE_ADMIN_ROLE)
    {
        FSMState storage state = _states[authorizationId][axis];
        if (!state.configured) revert FSMUnknown(authorizationId, axis);
        if (edgeRoot == bytes32(0)) {
            revert FSMEdgeNotInCommittedSet(authorizationId, 0, 0, bytes32(0));
        }
        state.edgeRoot = edgeRoot;
    }

    /// @notice Canonical leaf for an FSM transition edge (F-1).
    /// @dev Domain-separated under TAG_FSM_EDGE and bound to fsmHash so an edge
    ///      set committed for one FSM cannot be replayed against another.
    function edgeLeaf(bytes32 fsmHash, uint32 fromState, uint32 toState, bytes32 transitionId)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(TAG_FSM_EDGE, fsmHash, fromState, toState, transitionId));
    }

    /// @notice Advances the FSM state by exactly one valid transition.
    /// @dev MUST be called ONLY by ConditionEngine (msg.sender == _conditionEngine
    ///      else FSMUnauthorizedCaller). Validates: (a) FSM configured for the
    ///      (authorization, axis), (b) transitionId + attestationDigest non-zero,
    ///      (c) transitionId is a legal outgoing transition from current state,
    ///      (d) transitionProof verifies against the configured FSM bytecode.
    ///      Bumps cursorData by keccak(prev || transitionId || attestationDigest)
    ///      providing tamper-evident lineage.
    /// @param authorizationId target PDA authorization.
    /// @param axis CeremonyAxis.Reveal or CeremonyAxis.Shred.
    /// @param actor address that initiated the transition (passed through from ConditionEngine).
    /// @param transitionId requested transition identifier.
    /// @param attestationDigest oracle attestation hash bound to this transition.
    /// @param transitionProof FSM transition proof bytes (interpreter-specific).
    /// @return result FSMAdvanceResult containing new state, conditionRef, and events.
    function advanceFSM(
        bytes32 authorizationId,
        CeremonyAxis axis,
        address actor,
        bytes32 transitionId,
        bytes32 attestationDigest,
        bytes calldata transitionProof
    ) external returns (FSMAdvanceResult memory result) {
        if (msg.sender != _conditionEngine) revert FSMUnauthorizedCaller(msg.sender);
        _requireNotPaused();
        if (transitionId == bytes32(0) || attestationDigest == bytes32(0)) {
            revert FSMInvalidTransition(authorizationId, 0, transitionId);
        }

        FSMState storage state = _states[authorizationId][axis];
        if (!state.configured) revert FSMUnknown(authorizationId, axis);

        TransitionProof memory proof = abi.decode(transitionProof, (TransitionProof));
        if (proof.fsmHash != state.fsmHash) revert FSMHashMismatch(authorizationId, state.fsmHash, proof.fsmHash);
        if (proof.fromState != state.currentState) {
            revert FSMInvalidTransition(authorizationId, state.currentState, transitionId);
        }
        // F-1: the (fromState,toState,transitionId) edge MUST be a member of the
        // fsmHash-committed transition set (edgeRoot). Without this, a caller can
        // assert any toState (incl. a fabricated terminal state) and defeat the
        // multi-step sequence the FSM was meant to enforce. Fail-closed: a zero
        // edgeRoot (never bound, or just-overwritten) admits no edge.
        bytes32 leaf = edgeLeaf(state.fsmHash, proof.fromState, proof.toState, transitionId);
        if (state.edgeRoot == bytes32(0) || !MerkleProof.verify(proof.edgeProof, state.edgeRoot, leaf)) {
            revert FSMEdgeNotInCommittedSet(authorizationId, proof.fromState, proof.toState, transitionId);
        }
        if (proof.allowedSubmitter != address(0) && proof.allowedSubmitter != actor) {
            revert FSMUnauthorizedSubmitter(authorizationId, actor);
        }
        uint32 maxTransitions = proof.maxTransitions == 0 ? state.maxTransitions : proof.maxTransitions;
        if (state.transitionCount + 1 > maxTransitions) revert FSMGasBudgetExceeded(authorizationId);
        if (state.deadline != 0 && block.timestamp > state.deadline) {
            revert FSMInvalidTransition(authorizationId, state.currentState, transitionId);
        }

        uint32 fromState = state.currentState;
        state.currentState = proof.toState;
        state.terminalState = proof.terminalState == 0 ? state.terminalState : proof.terminalState;
        state.lastAdvancedAt = uint64(block.timestamp);
        state.deadline = proof.deadline == 0 ? state.deadline : proof.deadline;
        state.cursorData = keccak256(abi.encodePacked(state.cursorData, transitionId, attestationDigest));
        state.transitionCount += 1;

        bool terminal = state.currentState == state.terminalState;
        result =
            FSMAdvanceResult({ terminal: terminal, newState: state.currentState, conditionRef: proof.conditionRef });
        emit FSMAdvanced(authorizationId, axis, fromState, state.currentState, transitionId, terminal);
    }

    function currentState(bytes32 authorizationId, CeremonyAxis axis) external view returns (uint32) {
        FSMState memory state = _states[authorizationId][axis];
        if (!state.configured) revert FSMUnknown(authorizationId, axis);
        return state.currentState;
    }

    /// @notice Reads whether the FSM for (authorizationId, axis) has reached its
    ///         committed terminal state (F-1). The engine consumes this instead
    ///         of fabricating a 0→1 advance: terminal status is the real,
    ///         edge-validated FSM state, never a hardcoded assertion.
    /// @dev A just-configured FSM whose initialState already equals terminalState
    ///      is NOT treated as terminal (transitionCount == 0) — the FSM must be
    ///      driven through at least one validated edge to fire.
    function isTerminal(bytes32 authorizationId, CeremonyAxis axis) external view returns (bool) {
        FSMState memory state = _states[authorizationId][axis];
        if (!state.configured) revert FSMUnknown(authorizationId, axis);
        return state.transitionCount > 0 && state.currentState == state.terminalState;
    }

    function fsmState(bytes32 authorizationId, CeremonyAxis axis) external view returns (FSMState memory) {
        FSMState memory state = _states[authorizationId][axis];
        if (!state.configured) revert FSMUnknown(authorizationId, axis);
        return state;
    }

    function conditionEngine() external view returns (address) {
        return _conditionEngine;
    }

    function _requireNotPaused() private view {
        if (_pauses[GLOBAL_SCOPE].until != 0 && block.timestamp < _pauses[GLOBAL_SCOPE].until) {
            revert FSMPaused(GLOBAL_SCOPE);
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

    uint256[50] private __gap;
}
