// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { ShredRegistry } from "../../src/shred/ShredRegistry.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract ShredRegistryFuzzTest is Test {
    ShredRegistry internal shredReg;
    address internal timelock = address(0xA11CE);
    address internal mockConditionEngine = address(0xCAFE);

    function setUp() public {
        shredReg = ShredRegistry(
            ProxyDeploy.deployProxy(
                address(new ShredRegistry()), abi.encodeCall(ShredRegistry.initialize, (timelock, mockConditionEngine))
            )
        );
        vm.warp(1_000_000);
    }

    /// @notice Fuzz: requestShred MUST revert for any unknown commit (no PDA registered).
    /// @dev Mock condition engine has no PDA mapped, so any hCommit query reverts.
    function testFuzz_requestShred_UnknownCommitReverts(
        bytes32 authorizationId,
        bytes32 hCommit,
        bytes32 evidenceRef
    ) external {
        vm.expectRevert(); // mock condition engine returns 0 hCommit -> mismatch -> revert
        shredReg.requestShred(authorizationId, hCommit, evidenceRef);
    }

    /// @notice Fuzz: recordShredAuthorized MUST require msg.sender == ConditionEngine.
    function testFuzz_recordShredAuthorized_NonEngineReverts(
        address caller,
        bytes32 authorizationId,
        bytes32 hCommit,
        uint32 challengeWindow,
        bytes32 conditionRef
    ) external {
        vm.assume(caller != mockConditionEngine);
        vm.assume(caller != address(0));
        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(ShredRegistry.ShredUnauthorizedConditionEngine.selector, caller)
        );
        shredReg.recordShredAuthorized(authorizationId, hCommit, challengeWindow, conditionRef);
    }

    /// @notice Fuzz: finalizeShred MUST revert for unknown commits.
    function testFuzz_finalizeShred_UnknownCommitReverts(
        bytes32 authorizationId,
        bytes32 hCommit
    ) external {
        vm.expectRevert(); // unknown commit path
        shredReg.finalizeShred(authorizationId, hCommit);
    }

    /// @notice Fuzz: isShredded view returns false for any never-shredded commit.
    function testFuzz_isShredded_DefaultsFalse(bytes32 hCommit) external view {
        assertFalse(shredReg.isShredded(hCommit), "default state must be not-shredded");
    }
}
