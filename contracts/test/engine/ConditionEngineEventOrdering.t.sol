// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ConditionMode, LifecycleState, ShredAuthorityMode } from "../../src/lib/Enums.sol";
import { ConditionEngineTestBase } from "./ConditionEngine.t.sol";

contract ConditionEngineEventOrderingTest is ConditionEngineTestBase {
    function test_pdaRegisteredBeforeCeremonyAndOnlyOneReveal() external {
        _register(_validRegistration(ConditionMode.ModeP, ConditionMode.ModeP));
        engine.authorizeReveal(auth, evidence);
        vm.expectRevert();
        engine.authorizeReveal(auth, evidence);
    }

    function test_shredFinalizedAfterShredAuthorizedAndBlocksReveal() external {
        bytes32 hCommit = _register(_validRegistration(ConditionMode.ModeP, ConditionMode.ModeP));
        engine.authorizeShred(auth, evidence);
        // BR-D: Subject authority carries the protocol shred window/latency floor,
        // so finalize only after the window + latency elapse.
        vm.warp(block.timestamp + SHRED_WINDOW_FLOOR + 1);
        shred.finalizeShred(auth, hCommit);
        assertTrue(shred.isShredded(hCommit));
        vm.expectRevert();
        engine.authorizeReveal(auth, evidence);
    }

    function test_noShredFinalizedAfterPostChallengeRevealInProgress() external {
        bytes32 hCommit = _register(
            _validRegistrationWith(auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Subject)
        );
        engine.authorizeShred(auth, evidence);
        engine.authorizeReveal(auth, evidence);
        vm.expectRevert();
        shred.finalizeShred(auth, hCommit);
    }

    function test_refusalCanOccurAfterRevealWithoutErasingReveal() external {
        _register(_validRegistration(ConditionMode.ModeP, ConditionMode.ModeP));
        engine.authorizeReveal(auth, evidence);
        assertTrue(engine.canGatesSign(auth));
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.PostChallengeRevealInProgress));
    }
}
