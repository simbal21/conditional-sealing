// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import { ChallengeRegistry } from "../../src/challenge/ChallengeRegistry.sol";
import { ConditionEngine } from "../../src/engine/ConditionEngine.sol";
import { PaymentObligationModule } from "../../src/modules/PaymentObligationModule.sol";
import { PluginHashRegistry } from "../../src/registries/PluginHashRegistry.sol";

/// @title ImplInitLockedTest
/// @notice Regression proof for audit F-01: every upgradeable V3 implementation
///         calls `_disableInitializers()` in its constructor, so an attacker
///         cannot seize a freshly-deployed implementation by calling
///         `initialize(...)` directly on the impl address (bypassing the proxy).
/// @dev Representative coverage across the four impl families: standalone
///      single-arg registry, multi-arg registry (governed), condition module
///      (via ConditionModuleBase), and the engine. All share the same
///      `_disableInitializers()` constructor pattern, so a passing sample here
///      attests the uniform discipline verified file-by-file at review time.
contract ImplInitLockedTest is Test {
    function test_F01_challengeRegistryImplCannotBeInitializedDirectly() external {
        ChallengeRegistry impl = new ChallengeRegistry();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(0xA11CE));
    }

    function test_F01_pluginHashRegistryImplCannotBeInitializedDirectly() external {
        PluginHashRegistry impl = new PluginHashRegistry();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(0xA11CE), address(0xB0B), address(0xCAFE), address(0xDA7A), address(0xBEEF));
    }

    function test_F01_paymentObligationModuleImplCannotBeInitializedDirectly() external {
        PaymentObligationModule impl = new PaymentObligationModule();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(0xA11CE), address(0xB0B));
    }

    function test_F01_conditionEngineImplCannotBeInitializedDirectly() external {
        ConditionEngine impl = new ConditionEngine();
        ConditionEngine.EngineConfig memory config;
        config.timelock = address(0xA11CE);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(config);
    }
}
