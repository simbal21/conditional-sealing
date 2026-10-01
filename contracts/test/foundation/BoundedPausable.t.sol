// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { BoundedPausable } from "../../src/base/BoundedPausable.sol";
import { IPausableSurface } from "../../src/base/IPausableSurface.sol";
import { PauseAuthorityMode, PauseConstants } from "../../src/lib/Enums.sol";

/// @notice Default-cap surface (72-hour operational pause cap).
contract OperationalPausable is BoundedPausable {
    address internal immutable _admin;

    constructor(address admin) {
        _admin = admin;
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (caller != _admin) revert PauseUnauthorized(scope, caller);
    }
}

/// @notice Registry-cap surface (7-day cap via override).
contract RegistryPausable is BoundedPausable {
    address internal immutable _admin;

    constructor(address admin) {
        _admin = admin;
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (caller != _admin) revert PauseUnauthorized(scope, caller);
    }

    function _maxPauseDuration() internal pure override returns (uint64) {
        return PauseConstants.MAX_REGISTRY_PAUSE_SECONDS;
    }

    function _pauseAuthorityMode(bytes32) internal pure override returns (PauseAuthorityMode) {
        return PauseAuthorityMode.Joint;
    }
}

contract BoundedPausableTest is Test {
    OperationalPausable internal opPausable;
    RegistryPausable internal regPausable;

    address internal admin = address(0xA11CE);
    address internal stranger = address(0xBEEF);
    bytes32 internal constant SCOPE_A = keccak256("scope.a");
    bytes32 internal constant REASON_A = keccak256("reason.a");

    function setUp() public {
        opPausable = new OperationalPausable(admin);
        regPausable = new RegistryPausable(admin);
        // Set a deterministic block time so the "until" math is sane.
        vm.warp(1_000_000);
    }

    function test_pause_RevertsWhenUntilNotInFuture() external {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IPausableSurface.PauseUntilInvalid.selector, SCOPE_A, uint64(block.timestamp))
        );
        opPausable.pause(SCOPE_A, uint64(block.timestamp), REASON_A);
    }

    function test_pause_RevertsWhenDurationExceedsMaxOperational() external {
        uint64 maxUntil = uint64(block.timestamp) + PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
        uint64 tooFar = maxUntil + 1;
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IPausableSurface.PauseDurationTooLong.selector, SCOPE_A, tooFar, maxUntil)
        );
        opPausable.pause(SCOPE_A, tooFar, REASON_A);
    }

    function test_pause_AcceptsValidWindow_AndIsPausedReturnsTrue() external {
        uint64 until = uint64(block.timestamp + 3600);
        vm.expectEmit(true, false, false, true);
        emit IPausableSurface.PauseSet(SCOPE_A, until, REASON_A, PauseAuthorityMode.Partner);
        vm.prank(admin);
        opPausable.pause(SCOPE_A, until, REASON_A);

        (bool active, uint64 storedUntil, bytes32 storedReason) = opPausable.isPaused(SCOPE_A);
        assertTrue(active, "should be paused");
        assertEq(storedUntil, until, "until stored");
        assertEq(storedReason, REASON_A, "reason stored");
    }

    function test_isPaused_AutoExpiresAfterUntil() external {
        uint64 until = uint64(block.timestamp + 3600);
        vm.prank(admin);
        opPausable.pause(SCOPE_A, until, REASON_A);

        // Advance past `until`. Auto-expire path: active == false.
        vm.warp(until + 1);
        (bool active, uint64 storedUntil,) = opPausable.isPaused(SCOPE_A);
        assertFalse(active, "should auto-expire");
        // until is still recorded - clear by unpause.
        assertEq(storedUntil, until, "until preserved post-expire");
    }

    function test_unpause_ClearsEntry_AndEmits() external {
        uint64 until = uint64(block.timestamp + 3600);
        vm.prank(admin);
        opPausable.pause(SCOPE_A, until, REASON_A);

        vm.expectEmit(true, false, false, true);
        emit IPausableSurface.PauseCleared(SCOPE_A);
        vm.prank(admin);
        opPausable.unpause(SCOPE_A);

        (bool active, uint64 storedUntil, bytes32 storedReason) = opPausable.isPaused(SCOPE_A);
        assertFalse(active, "no longer paused");
        assertEq(storedUntil, 0, "until cleared");
        assertEq(storedReason, bytes32(0), "reason cleared");
    }

    function test_pause_UnauthorizedCallerReverts() external {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IPausableSurface.PauseUnauthorized.selector, SCOPE_A, stranger));
        opPausable.pause(SCOPE_A, uint64(block.timestamp + 3600), REASON_A);
    }

    function test_unpause_UnauthorizedCallerReverts() external {
        vm.prank(admin);
        opPausable.pause(SCOPE_A, uint64(block.timestamp + 3600), REASON_A);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IPausableSurface.PauseUnauthorized.selector, SCOPE_A, stranger));
        opPausable.unpause(SCOPE_A);
    }

    function test_registryOverride_AcceptsSevenDayPause() external {
        // Operational surface rejects 7d > 72h cap.
        uint64 sevenDayUntil = uint64(block.timestamp) + PauseConstants.MAX_REGISTRY_PAUSE_SECONDS;
        uint64 opMaxUntil = uint64(block.timestamp) + PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IPausableSurface.PauseDurationTooLong.selector, SCOPE_A, sevenDayUntil, opMaxUntil)
        );
        opPausable.pause(SCOPE_A, sevenDayUntil, REASON_A);

        // Registry surface accepts the same window (7d <= 7d cap).
        vm.expectEmit(true, false, false, true);
        emit IPausableSurface.PauseSet(SCOPE_A, sevenDayUntil, REASON_A, PauseAuthorityMode.Joint);
        vm.prank(admin);
        regPausable.pause(SCOPE_A, sevenDayUntil, REASON_A);
        (bool active,,) = regPausable.isPaused(SCOPE_A);
        assertTrue(active, "registry surface accepts 7-day pause");
    }

    function test_pauseConstants_HardcodedValues() external pure {
        assertEq(PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS, 259200, "72 hours");
        assertEq(PauseConstants.MAX_REGISTRY_PAUSE_SECONDS, 604800, "7 days");
        assertEq(PauseConstants.MAX_EMERGENCY_PAUSE_SECONDS, 604800, "7 days");
    }
}
