// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { BoundedPausable } from "../../src/base/BoundedPausable.sol";
import { IPausableSurface } from "../../src/base/IPausableSurface.sol";
import { PauseAuthorityMode, PauseConstants } from "../../src/lib/Enums.sol";

contract OperationalPausable is BoundedPausable {
    address internal immutable _admin;

    constructor(address admin) {
        _admin = admin;
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (caller != _admin) revert PauseUnauthorized(scope, caller);
    }
}

contract BoundedPausableFuzzTest is Test {
    OperationalPausable internal opPausable;
    address internal admin = address(0xA11CE);

    function setUp() public {
        opPausable = new OperationalPausable(admin);
        vm.warp(1_000_000);
    }

    /// @notice Fuzz: pause MUST revert when until <= now for any scope/reason.
    function testFuzz_pause_RevertsWhenUntilNotInFuture(bytes32 scope, bytes32 reason, uint64 untilDelta) external {
        // untilDelta capped to [0, block.timestamp] so until <= now
        uint64 nowTs = uint64(block.timestamp);
        uint64 until = uint64(untilDelta % (nowTs + 1));
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IPausableSurface.PauseUntilInvalid.selector, scope, until));
        opPausable.pause(scope, until, reason);
    }

    /// @notice Fuzz: pause MUST revert when window exceeds the 72-hour operational cap.
    function testFuzz_pause_RevertsWhenDurationExceedsCap(bytes32 scope, bytes32 reason, uint64 extra) external {
        // extra >= 1 ensures until > maxUntil
        uint64 boundedExtra = (extra % (type(uint64).max - PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS - uint64(block.timestamp) - 1)) + 1;
        uint64 maxUntil = uint64(block.timestamp) + PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
        uint64 tooFar = maxUntil + boundedExtra;
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IPausableSurface.PauseDurationTooLong.selector, scope, tooFar, maxUntil));
        opPausable.pause(scope, tooFar, reason);
    }

    /// @notice Fuzz: any until in (now, now+72h] is accepted and isPaused returns true.
    function testFuzz_pause_AcceptsAnyValidWindow(bytes32 scope, bytes32 reason, uint64 delta) external {
        // delta in [1, MAX_OPERATIONAL_PAUSE_SECONDS]
        uint64 boundedDelta = (delta % PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS) + 1;
        uint64 until = uint64(block.timestamp) + boundedDelta;
        vm.prank(admin);
        opPausable.pause(scope, until, reason);
        (bool active, uint64 storedUntil, bytes32 storedReason) = opPausable.isPaused(scope);
        assertTrue(active, "should be paused for any valid window");
        assertEq(storedUntil, until, "until stored");
        assertEq(storedReason, reason, "reason stored");
    }

    /// @notice Fuzz: isPaused MUST auto-expire for any block.timestamp > until.
    function testFuzz_isPaused_AutoExpiresAtAnyOffset(bytes32 scope, uint64 delta, uint32 jumpOffset) external {
        uint64 boundedDelta = (delta % PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS) + 1;
        uint64 until = uint64(block.timestamp) + boundedDelta;
        vm.prank(admin);
        opPausable.pause(scope, until, bytes32(0));

        // Warp to until + jumpOffset + 1 (always past expiry)
        vm.warp(until + uint64(jumpOffset) + 1);
        (bool active,,) = opPausable.isPaused(scope);
        assertFalse(active, "should auto-expire at any offset past until");
    }

    /// @notice Fuzz: unpause MUST clear the entry regardless of remaining time.
    function testFuzz_unpause_ClearsEntryAtAnyTime(bytes32 scope, bytes32 reason, uint64 delta, uint32 jumpBefore)
        external
    {
        uint64 boundedDelta = (delta % PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS) + 1;
        uint64 until = uint64(block.timestamp) + boundedDelta;
        vm.prank(admin);
        opPausable.pause(scope, until, reason);

        // Warp forward but stay before until
        uint64 jump = uint64(jumpBefore) % boundedDelta;
        vm.warp(block.timestamp + jump);
        vm.prank(admin);
        opPausable.unpause(scope);

        (bool active, uint64 storedUntil, bytes32 storedReason) = opPausable.isPaused(scope);
        assertFalse(active, "unpause clears active");
        assertEq(storedUntil, 0, "unpause clears until");
        assertEq(storedReason, bytes32(0), "unpause clears reason");
    }

    /// @notice Fuzz: unauthorized callers MUST always revert PauseUnauthorized.
    function testFuzz_pause_AnyStrangerReverts(address stranger, bytes32 scope, bytes32 reason, uint64 delta) external {
        vm.assume(stranger != admin);
        vm.assume(stranger != address(0));
        uint64 boundedDelta = (delta % PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS) + 1;
        uint64 until = uint64(block.timestamp) + boundedDelta;
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IPausableSurface.PauseUnauthorized.selector, scope, stranger));
        opPausable.pause(scope, until, reason);
    }
}
