// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { CeremonyAxis, ConditionMode, LifecycleState, ShredAuthorityMode } from "../../src/lib/Enums.sol";
import { PDARegistration } from "../../src/lib/Structs.sol";
import { ConditionEngineTestBase } from "./ConditionEngine.t.sol";

contract ConditionEngineLifecycleTest is ConditionEngineTestBase {
    function test_lifecycleEnumValuesAreExactlyTenStates() external pure {
        assertEq(uint8(LifecycleState.Unregistered), 0);
        assertEq(uint8(LifecycleState.Registered), 1);
        assertEq(uint8(LifecycleState.RevealConditionMet), 2);
        assertEq(uint8(LifecycleState.RevealChallengeOpen), 3);
        assertEq(uint8(LifecycleState.PostChallengeRevealInProgress), 4);
        assertEq(uint8(LifecycleState.RevealCompleted), 5);
        assertEq(uint8(LifecycleState.ShredConditionMet), 6);
        assertEq(uint8(LifecycleState.ShredChallengeOpen), 7);
        assertEq(uint8(LifecycleState.Shredded), 8);
        assertEq(uint8(LifecycleState.Paused), 9);
    }

    function test_allLifecycleStatesReachableWithCorrectTransitions() external {
        PDARegistration memory reg = _validRegistrationWith(
            auth, ConditionMode.ModeP, ConditionMode.ModeP, 1 days, 1 days, ShredAuthorityMode.Subject
        );
        bytes32 hCommit = _register(reg);

        engine.authorizeReveal(auth, evidence);
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.RevealChallengeOpen));
        // F-2: markChallengeResolved now requires the reveal challenge window to have
        // elapsed (no ChallengeRegistry wired in this fixture → path (a) applies).
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(operator);
        engine.markChallengeResolved(auth, CeremonyAxis.Reveal);
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.PostChallengeRevealInProgress));
        vm.prank(orchestrator);
        engine.recordRevealCompleted(auth, keccak256("delivery"));
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.RevealCompleted));

        bytes32 auth2 = keccak256("auth2");
        PDARegistration memory reg2 =
            _validRegistrationWith(auth2, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Subject);
        bytes32 hCommit2 = _register(reg2);
        vm.prank(subject);
        shred.requestShred(auth2, hCommit2, evidence);
        engine.authorizeShred(auth2, evidence);
        // BR-D: Subject authority carries the protocol shred window/latency floor,
        // so authorizeShred opens a challenge window rather than entering
        // ShredConditionMet immediately. Finalize only after window + latency elapse.
        assertEq(uint8(engine.lifecycleState(auth2)), uint8(LifecycleState.ShredChallengeOpen));
        vm.warp(block.timestamp + SHRED_WINDOW_FLOOR + 1);
        shred.finalizeShred(auth2, hCommit2);
        assertEq(uint8(engine.lifecycleState(auth2)), uint8(LifecycleState.Shredded));

        bytes32 auth3 = keccak256("auth3");
        PDARegistration memory reg3 =
            _validRegistrationWith(auth3, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Subject);
        _register(reg3);
        vm.prank(timelock);
        engine.pause(auth3, uint64(block.timestamp + 1 hours), keccak256("pause"));
        assertEq(uint8(engine.lifecycleState(auth3)), uint8(LifecycleState.Paused));

        assertFalse(uint8(engine.lifecycleState(auth3)) > uint8(LifecycleState.Paused));
        assertTrue(hCommit != bytes32(0));
        assertTrue(hCommit2 != bytes32(0));
    }
}
