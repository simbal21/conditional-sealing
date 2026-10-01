// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ConditionMode, ShredAuthorityMode, ShredState } from "../../src/lib/Enums.sol";
import { PDARegistration } from "../../src/lib/Structs.sol";
import { ShredRegistry } from "../../src/shred/ShredRegistry.sol";
import { ConditionEngineTestBase } from "../engine/ConditionEngine.t.sol";

contract ShredRegistryTest is ConditionEngineTestBase {
    event ShredRequested(bytes32 indexed authorizationId, bytes32 indexed hCommit, ShredAuthorityMode authorityMode);
    event ShredFinalized(bytes32 indexed authorizationId, bytes32 indexed hCommit, bytes32 proofShred);

    function test_requestShredPositiveAndStateProgression() external {
        bytes32 hCommit = _register(_validRegistration(ConditionMode.ModeP, ConditionMode.ModeP));
        vm.expectEmit(true, true, false, true, address(shred));
        emit ShredRequested(auth, hCommit, ShredAuthorityMode.Subject);
        vm.prank(subject);
        shred.requestShred(auth, hCommit, evidence);
        assertEq(uint8(shred.currentShredState(hCommit)), uint8(ShredState.Requested));
    }

    function test_requestShredRejectsNoneAuthority() external {
        PDARegistration memory reg =
            _validRegistrationWith(auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.None);
        bytes32 hCommit = _register(reg);
        vm.prank(subject);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredAuthorityInvalid.selector, hCommit, subject));
        shred.requestShred(auth, hCommit, evidence);
    }

    function test_requestShredRejectsDisabledAuthority() external {
        PDARegistration memory reg =
            _validRegistrationWith(auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Disabled);
        bytes32 hCommit = _register(reg);
        vm.prank(subject);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredAuthorityInvalid.selector, hCommit, subject));
        shred.requestShred(auth, hCommit, evidence);
    }

    function test_recordShredAuthorizedFromNonEngineReverts() external {
        bytes32 hCommit = _register(_validRegistration(ConditionMode.ModeP, ConditionMode.ModeP));
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredUnauthorizedConditionEngine.selector, address(this)));
        shred.recordShredAuthorized(auth, hCommit, 0, keccak256("condition"));
    }

    function test_finalizeShredReturnsProofAndSetsShredded() external {
        bytes32 hCommit = _register(_validRegistration(ConditionMode.ModeP, ConditionMode.ModeP));
        engine.authorizeShred(auth, evidence);
        // BR-D: shred latency floor (1 days) makes finalize non-immediate; warp past it.
        vm.warp(block.timestamp + 1 days + 1);
        bytes32 expected = keccak256(
            abi.encodePacked(
                auth, hCommit, uint64(block.number), uint8(ShredAuthorityMode.Subject), keccak256("shred-condition")
            )
        );
        vm.expectEmit(true, true, false, true, address(shred));
        emit ShredFinalized(auth, hCommit, expected);
        bytes32 proofShred = shred.finalizeShred(auth, hCommit);
        assertEq(proofShred, expected);
        assertTrue(shred.isShredded(hCommit));
        assertEq(uint8(shred.currentShredState(hCommit)), uint8(ShredState.Shredded));
    }

    function test_operatorAuthorityRequiresOperatorRole() external {
        PDARegistration memory reg =
            _validRegistrationWith(auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Operator);
        bytes32 hCommit = _register(reg);
        vm.prank(subject);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredAuthorityInvalid.selector, hCommit, subject));
        shred.requestShred(auth, hCommit, evidence);

        vm.prank(operator);
        shred.requestShred(auth, hCommit, evidence);
        assertEq(uint8(shred.currentShredState(hCommit)), uint8(ShredState.Requested));
    }

    function test_shredRegistryDoesNotDeclareShredAuthorizedEvent() external view {
        string memory source = vm.readFile("src/shred/ShredRegistry.sol");
        assertFalse(_contains(source, "event ShredAuthorized"));
    }

    function test_uupsUpgradeByNonTimelockReverts() external {
        ShredRegistry newImplementation = new ShredRegistry();
        vm.expectRevert();
        shred.upgradeToAndCall(address(newImplementation), "");
    }

    function _contains(string memory haystack, string memory needle) private pure returns (bool) {
        bytes memory h = bytes(haystack);
        bytes memory n = bytes(needle);
        if (n.length == 0 || h.length < n.length) return false;
        for (uint256 i = 0; i <= h.length - n.length; ++i) {
            bool ok = true;
            for (uint256 j = 0; j < n.length; ++j) {
                if (h[i + j] != n[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    }
}
