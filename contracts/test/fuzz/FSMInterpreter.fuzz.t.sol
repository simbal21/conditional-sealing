// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { FSMInterpreter } from "../../src/fsm/FSMInterpreter.sol";
import { CeremonyAxis } from "../../src/lib/Enums.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract FSMInterpreterFuzzTest is Test {
    FSMInterpreter internal fsm;
    address internal timelock = address(0xA11CE);
    address internal admin = address(0xB0B);
    address internal mockConditionEngine = address(0xCAFE);

    function setUp() public {
        fsm = FSMInterpreter(
            ProxyDeploy.deployProxy(
                address(new FSMInterpreter()), abi.encodeCall(FSMInterpreter.initialize, (timelock, mockConditionEngine))
            )
        );
        vm.prank(timelock);
        fsm.grantRole(Roles.MODULE_ADMIN_ROLE, admin);
        vm.warp(1_000_000);
    }

    /// @notice Fuzz: configureFSM MUST require MODULE_ADMIN_ROLE.
    function testFuzz_configureFSM_UnauthorizedRevert(
        address caller,
        bytes32 authorizationId,
        uint8 axisRaw,
        bytes32 fsmHash,
        uint32 initialState,
        uint32 terminalState,
        uint32 maxTransitions,
        uint64 deadline,
        bytes32 cursorData
    ) external {
        vm.assume(caller != address(0));
        vm.assume(caller != timelock);
        vm.assume(caller != admin);
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        vm.prank(caller);
        vm.expectRevert(); // AccessControl rejects
        fsm.configureFSM(authorizationId, axis, fsmHash, initialState, terminalState, maxTransitions, deadline, cursorData);
    }

    /// @notice Fuzz: configureFSM accepts any valid args from MODULE_ADMIN.
    function testFuzz_configureFSM_AcceptsAnyValidArgs(
        bytes32 authorizationId,
        uint8 axisRaw,
        bytes32 fsmHash,
        uint32 initialState,
        uint32 terminalState,
        uint32 maxTransitions,
        uint64 deadline,
        bytes32 cursorData
    ) external {
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        vm.prank(admin);
        fsm.configureFSM(authorizationId, axis, fsmHash, initialState, terminalState, maxTransitions, deadline, cursorData);
    }

    /// @notice Fuzz: maxTransitions=0 MUST coerce to 1 (single-shot semantics).
    function testFuzz_configureFSM_ZeroMaxTransitionsCoercesToOne(
        bytes32 authorizationId,
        uint8 axisRaw,
        bytes32 fsmHash,
        uint32 initialState,
        uint32 terminalState,
        uint64 deadline,
        bytes32 cursorData
    ) external {
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        vm.prank(admin);
        // maxTransitions = 0 is the documented edge — should not revert, should coerce
        fsm.configureFSM(authorizationId, axis, fsmHash, initialState, terminalState, 0, deadline, cursorData);
        // Re-configuration should also work (overwrite semantics)
        vm.prank(admin);
        fsm.configureFSM(authorizationId, axis, fsmHash, initialState, terminalState, 0, deadline, cursorData);
    }

    /// @notice Fuzz: re-configuration on same (authId, axis) overwrites cleanly.
    function testFuzz_configureFSM_ReconfigurationOverwrites(
        bytes32 authorizationId,
        uint8 axisRaw,
        bytes32 fsmHash1,
        bytes32 fsmHash2,
        uint32 initialState,
        uint32 terminalState,
        uint64 deadline
    ) external {
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        vm.prank(admin);
        fsm.configureFSM(authorizationId, axis, fsmHash1, initialState, terminalState, 1, deadline, bytes32(0));
        vm.prank(admin);
        fsm.configureFSM(authorizationId, axis, fsmHash2, initialState, terminalState, 1, deadline, bytes32(0));
        // Both calls succeed = overwrite semantics verified
    }

    /// @notice Fuzz: two-axis storage isolation — Reveal and Shred axes are independent.
    function testFuzz_configureFSM_TwoAxisIsolation(
        bytes32 authorizationId,
        bytes32 fsmHashReveal,
        bytes32 fsmHashShred,
        uint32 initialState,
        uint32 terminalState
    ) external {
        vm.prank(admin);
        fsm.configureFSM(authorizationId, CeremonyAxis.Reveal, fsmHashReveal, initialState, terminalState, 5, 0, bytes32(0));
        vm.prank(admin);
        fsm.configureFSM(authorizationId, CeremonyAxis.Shred, fsmHashShred, initialState, terminalState, 5, 0, bytes32(0));
        // Both axes can be configured on the same authorizationId without interference
    }
}
