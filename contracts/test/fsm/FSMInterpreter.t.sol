// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";

import { FSMInterpreter } from "../../src/fsm/FSMInterpreter.sol";
import { IFSMInterpreter } from "../../src/engine/IConditionEngine.sol";
import { CeremonyAxis } from "../../src/lib/Enums.sol";
import { FSMAdvanceResult } from "../../src/lib/Structs.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract FSMInterpreterTest is Test {
    FSMInterpreter internal fsm;
    address internal engine = address(0xE11E);
    address internal actor = address(0xA11CE);
    bytes32 internal auth = keccak256("auth");
    bytes32 internal fsmHash = keccak256("fsm");
    bytes32 internal badFsmHash = keccak256("bad-fsm");
    bytes32 internal transitionId = keccak256("transition");
    bytes32 internal digest = keccak256("digest");

    function setUp() public {
        vm.warp(1_000_000);
        fsm = FSMInterpreter(
            ProxyDeploy.deployProxy(
                address(new FSMInterpreter()), abi.encodeCall(FSMInterpreter.initialize, (address(this), engine))
            )
        );
        fsm.configureFSM(auth, CeremonyAxis.Reveal, fsmHash, 1, 2, 2, uint64(block.timestamp + 1 days), bytes32(0));
        // F-1: bind the single legal edge 1->2 under transitionId.
        fsm.configureFSMEdges(auth, CeremonyAxis.Reveal, fsm.edgeLeaf(fsmHash, 1, 2, transitionId));
    }

    function test_advanceFSM_OnlyConditionEngineAndTerminal() external {
        vm.prank(actor);
        vm.expectRevert(abi.encodeWithSelector(IFSMInterpreter.FSMUnauthorizedCaller.selector, actor));
        fsm.advanceFSM(auth, CeremonyAxis.Reveal, actor, transitionId, digest, _proof(fsmHash, 1, 2, 2, 2, actor));

        vm.prank(engine);
        FSMAdvanceResult memory result =
            fsm.advanceFSM(auth, CeremonyAxis.Reveal, actor, transitionId, digest, _proof(fsmHash, 1, 2, 2, 2, actor));
        assertTrue(result.terminal);
        assertEq(result.newState, 2);
        assertEq(fsm.currentState(auth, CeremonyAxis.Reveal), 2);
        assertTrue(fsm.isTerminal(auth, CeremonyAxis.Reveal));
    }

    function test_invalidTransitionHashAndBudgetRevert() external {
        vm.prank(engine);
        vm.expectRevert(abi.encodeWithSelector(IFSMInterpreter.FSMHashMismatch.selector, auth, fsmHash, badFsmHash));
        fsm.advanceFSM(auth, CeremonyAxis.Reveal, actor, transitionId, digest, _proof(badFsmHash, 1, 2, 2, 2, actor));

        bytes32 other = keccak256("other");
        fsm.configureFSM(other, CeremonyAxis.Reveal, fsmHash, 1, 9, 1, uint64(block.timestamp + 1 days), bytes32(0));
        // Bind a two-edge set so 1->2 and 2->3 are both legal members.
        bytes32 leafA = fsm.edgeLeaf(fsmHash, 1, 2, transitionId);
        bytes32 leafB = fsm.edgeLeaf(fsmHash, 2, 3, keccak256("next"));
        (bytes32 root, bytes32[] memory proofA, bytes32[] memory proofB) = _twoLeafTree(leafA, leafB);
        fsm.configureFSMEdges(other, CeremonyAxis.Reveal, root);

        vm.prank(engine);
        fsm.advanceFSM(other, CeremonyAxis.Reveal, actor, transitionId, digest, _proofWith(fsmHash, 1, 2, 9, 1, actor, proofA));
        vm.prank(engine);
        vm.expectRevert(abi.encodeWithSelector(IFSMInterpreter.FSMGasBudgetExceeded.selector, other));
        fsm.advanceFSM(
            other, CeremonyAxis.Reveal, actor, keccak256("next"), digest, _proofWith(fsmHash, 2, 3, 9, 1, actor, proofB)
        );
    }

    // ── F-1 closure: fabricated / non-committed edges are rejected ──────────────

    /// @notice F-1 (CRITICAL): a transition whose (fromState,toState,transitionId)
    ///         edge is NOT a member of the fsmHash-committed edge set MUST revert.
    ///         Against the vulnerable code (no edge validation, terminal=from==to)
    ///         this advance would succeed and fire terminal on the first call —
    ///         defeating the multi-step sequence the FSM enforces.
    function test_F1_advanceFSM_RejectsEdgeNotInCommittedSet() external {
        // Caller asserts a fabricated jump 1->2 under a DIFFERENT transitionId that
        // was never committed to the edge set. The fromState matches currentState
        // and the toState equals terminalState, so the OLD code would mark terminal.
        bytes32 forgedTransition = keccak256("forged");
        vm.prank(engine);
        vm.expectRevert(
            abi.encodeWithSelector(FSMInterpreter.FSMEdgeNotInCommittedSet.selector, auth, uint32(1), uint32(2), forgedTransition)
        );
        fsm.advanceFSM(auth, CeremonyAxis.Reveal, actor, forgedTransition, digest, _proof(fsmHash, 1, 2, 2, 2, actor));

        // State untouched: no fabricated terminal firing occurred.
        assertEq(fsm.currentState(auth, CeremonyAxis.Reveal), 1);
        assertFalse(fsm.isTerminal(auth, CeremonyAxis.Reveal));
    }

    /// @notice F-1: a caller cannot fabricate an arbitrary toState (e.g. directly
    ///         jumping to the terminal state via an edge that does not exist).
    function test_F1_advanceFSM_RejectsFabricatedToState() external {
        // The committed edge is 1->2. Caller tries 1->2 but lies that some other
        // edge transitionId authorizes it; equivalently a 1->5 jump never committed.
        vm.prank(engine);
        vm.expectRevert(
            abi.encodeWithSelector(FSMInterpreter.FSMEdgeNotInCommittedSet.selector, auth, uint32(1), uint32(5), transitionId)
        );
        fsm.advanceFSM(auth, CeremonyAxis.Reveal, actor, transitionId, digest, _proof(fsmHash, 1, 5, 5, 2, actor));
    }

    /// @notice F-1: an FSM whose edge set was never bound (configureFSM only) MUST
    ///         fail closed — no advance is possible against a zero edgeRoot.
    function test_F1_advanceFSM_FailsClosedWhenEdgeRootUnset() external {
        bytes32 noEdges = keccak256("no-edges");
        fsm.configureFSM(noEdges, CeremonyAxis.Reveal, fsmHash, 1, 2, 1, 0, bytes32(0));
        vm.prank(engine);
        vm.expectRevert(
            abi.encodeWithSelector(FSMInterpreter.FSMEdgeNotInCommittedSet.selector, noEdges, uint32(1), uint32(2), transitionId)
        );
        fsm.advanceFSM(noEdges, CeremonyAxis.Reveal, actor, transitionId, digest, _proof(fsmHash, 1, 2, 2, 1, actor));
    }

    /// @notice F-1: configureFSMEdges rejects a zero root (would re-open fail-open).
    function test_F1_configureFSMEdges_RejectsZeroRoot() external {
        vm.expectRevert(
            abi.encodeWithSelector(FSMInterpreter.FSMEdgeNotInCommittedSet.selector, auth, uint32(0), uint32(0), bytes32(0))
        );
        fsm.configureFSMEdges(auth, CeremonyAxis.Reveal, bytes32(0));
    }

    function _proof(bytes32 hash, uint32 from, uint32 to, uint32 terminal, uint32 maxTransitions, address allowed)
        private
        pure
        returns (bytes memory)
    {
        return _proofWith(hash, from, to, terminal, maxTransitions, allowed, new bytes32[](0));
    }

    function _proofWith(
        bytes32 hash,
        uint32 from,
        uint32 to,
        uint32 terminal,
        uint32 maxTransitions,
        address allowed,
        bytes32[] memory edgeProof
    ) private pure returns (bytes memory) {
        return abi.encode(
            FSMInterpreter.TransitionProof({
                fsmHash: hash,
                fromState: from,
                toState: to,
                terminalState: terminal,
                maxTransitions: maxTransitions,
                allowedSubmitter: allowed,
                conditionRef: keccak256("condition"),
                deadline: 0,
                edgeProof: edgeProof
            })
        );
    }

    /// @dev Builds a 2-leaf merkle tree matching OZ MerkleProof (sorted-pair hashing)
    ///      and returns the root + the single-element proof for each leaf.
    function _twoLeafTree(bytes32 leafA, bytes32 leafB)
        private
        pure
        returns (bytes32 root, bytes32[] memory proofA, bytes32[] memory proofB)
    {
        root = leafA <= leafB
            ? keccak256(abi.encodePacked(leafA, leafB))
            : keccak256(abi.encodePacked(leafB, leafA));
        proofA = new bytes32[](1);
        proofA[0] = leafB;
        proofB = new bytes32[](1);
        proofB[0] = leafA;
    }
}
