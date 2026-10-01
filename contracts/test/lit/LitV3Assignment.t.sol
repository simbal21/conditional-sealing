// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { LitV3Assignment } from "../../src/lit/LitV3Assignment.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract LitV3AssignmentTest is Test {
    LitV3Assignment internal mirror;

    address internal timelock = address(0x2001);
    address internal bridge = address(0x2002);
    address internal stranger = address(0x2003);

    bytes32 internal auth = keccak256("auth");

    function setUp() public {
        mirror = LitV3Assignment(
            ProxyDeploy.deployProxy(
                address(new LitV3Assignment()), abi.encodeCall(LitV3Assignment.initialize, (timelock))
            )
        );
        vm.prank(timelock);
        mirror.grantRole(Roles.LIT_GOVERNANCE_BRIDGE_ROLE, bridge);
    }

    function test_bridgeOnlyWrites() external {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(LitV3Assignment.LitUnauthorizedBridge.selector, stranger));
        mirror.recordAssignment(auth, keccak256("tee"), 11, hex"aa", keccak256("gov"));
    }

    function test_recordAssignmentAndRead() external {
        vm.expectEmit(true, true, false, true);
        emit LitV3Assignment.LitAssignmentRecorded(auth, keccak256("tee"), 11, keccak256("gov"));
        vm.prank(bridge);
        mirror.recordAssignment(auth, keccak256("tee"), 11, hex"aa", keccak256("gov"));

        (bytes32 tee, uint64 assignmentBlock, bytes memory pubkey, bytes32 digest) = mirror.getAssignment(auth);
        assertEq(tee, keccak256("tee"));
        assertEq(assignmentBlock, 11);
        assertEq(pubkey, hex"aa");
        assertEq(digest, keccak256("gov"));
    }

    function test_appendOnlyAndCorrectionPreservesPriorRecord() external {
        vm.prank(bridge);
        mirror.recordAssignment(auth, keccak256("tee-1"), 11, hex"aa", keccak256("gov-1"));

        vm.prank(bridge);
        vm.expectRevert(abi.encodeWithSelector(LitV3Assignment.LitAssignmentExists.selector, auth));
        mirror.recordAssignment(auth, keccak256("tee-2"), 12, hex"bb", keccak256("gov-2"));

        vm.prank(bridge);
        mirror.recordCorrection(auth, keccak256("tee-2"), 12, hex"bb", keccak256("gov-2"));

        assertEq(mirror.assignmentHistoryLength(auth), 2);
        LitV3Assignment.AssignmentRecord memory first = mirror.getAssignmentAt(auth, 0);
        LitV3Assignment.AssignmentRecord memory second = mirror.getAssignmentAt(auth, 1);
        assertEq(first.assignedTeeId, keccak256("tee-1"));
        assertFalse(first.correction);
        assertEq(second.assignedTeeId, keccak256("tee-2"));
        assertTrue(second.correction);
    }
}
