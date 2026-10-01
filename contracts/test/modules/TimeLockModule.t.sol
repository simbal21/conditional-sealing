// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ITimeLockModule } from "../../src/engine/IConditionEngine.sol";
import { TimeLockModule } from "../../src/modules/TimeLockModule.sol";
import { ModuleTestBase } from "./PaymentObligationModule.t.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract TimeLockModuleTest is ModuleTestBase {
    TimeLockModule internal module;

    function setUp() public {
        vm.warp(1_000_000);
        module = TimeLockModule(
            ProxyDeploy.deployProxy(
                address(new TimeLockModule()), abi.encodeCall(TimeLockModule.initialize, (timelock, engine))
            )
        );
    }

    function test_timeLockChainNativeAndWindow() external {
        _assertNoAuthorizationEvents("src/modules/TimeLockModule.sol");
        uint64 target = uint64(block.timestamp + 100);
        module.configureTimeWindow(auth, configDigest, target, target + 100, 0);
        assertFalse(module.evaluateTimeLock(auth));
        vm.expectRevert(
            abi.encodeWithSelector(ITimeLockModule.TimeLockNotReached.selector, auth, target, uint64(block.timestamp))
        );
        module.advance(auth, bytes32(0), "");

        vm.warp(target);
        assertTrue(module.advance(auth, bytes32(0), ""));
        assertTrue(module.evaluateTimeLock(auth));
    }

    function test_invalidTargetReverts() external {
        vm.expectRevert(abi.encodeWithSelector(ITimeLockModule.TimeLockTargetInvalid.selector, auth));
        module.configureTimeLock(auth, configDigest, 0, 0);
    }
}
