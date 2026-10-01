// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ConditionMode, ShredAuthorityMode } from "../../src/lib/Enums.sol";
import { ShredRegistry } from "../../src/shred/ShredRegistry.sol";
import { ConditionEngineTestBase } from "../engine/ConditionEngine.t.sol";

contract ShredGuardrailTest is ConditionEngineTestBase {
    function test_requestShredRevertsDuringPostChallengeRevealInProgress() external {
        bytes32 hCommit = _register(_validRegistration(ConditionMode.ModeP, ConditionMode.ModeP));
        engine.authorizeReveal(auth, evidence);
        vm.prank(subject);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredRevealInProgress.selector, auth));
        shred.requestShred(auth, hCommit, evidence);
    }

    function test_requestShredSucceedsWhenRegisteredNoRevealInProgress() external {
        bytes32 hCommit = _register(_validRegistration(ConditionMode.ModeP, ConditionMode.ModeP));
        vm.prank(subject);
        shred.requestShred(auth, hCommit, evidence);
    }

    function test_finalizeShredReReadsGuardrailAfterRevealRace() external {
        bytes32 hCommit = _register(
            _validRegistrationWith(auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Subject)
        );
        engine.authorizeShred(auth, evidence);
        engine.authorizeReveal(auth, evidence);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredRevealInProgress.selector, auth));
        shred.finalizeShred(auth, hCommit);
    }
}
