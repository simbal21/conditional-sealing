// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { CealisIdentifierHelpers } from "../../src/helpers/CealisIdentifierHelpers.sol";
import { SupersededCommitRegistry } from "../../src/superseded/SupersededCommitRegistry.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract SupersededCommitRegistryTest is Test {
    CealisIdentifierHelpers internal helpers;
    SupersededCommitRegistry internal registry;

    address internal timelock = address(0x3001);
    address internal stranger = address(0x3002);

    bytes32 internal oldCommit = keccak256("old");
    bytes32 internal newCommit = keccak256("new");
    bytes32 internal govRef = keccak256("gov");

    function setUp() public {
        helpers = new CealisIdentifierHelpers();
        registry = SupersededCommitRegistry(
            ProxyDeploy.deployProxy(
                address(new SupersededCommitRegistry()),
                abi.encodeCall(SupersededCommitRegistry.initialize, (timelock, address(helpers)))
            )
        );
    }

    function test_recordSupersessionRequiresRekeyGovernanceRole() external {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(SupersededCommitRegistry.SupersessionUnauthorized.selector, stranger));
        registry.recordSupersession(oldCommit, newCommit, 1, govRef);
    }

    function test_recordSupersessionThroughTimelockRoleSucceeds() external {
        vm.warp(block.timestamp + 7 days);
        vm.prank(timelock);
        registry.recordSupersession(oldCommit, newCommit, 1, govRef);

        (bytes32 successor, uint16 generation) = registry.successorOf(oldCommit);
        assertEq(successor, newCommit);
        assertEq(generation, 1);
    }

    function test_generationOverflowRejected() external {
        vm.prank(timelock);
        vm.expectRevert(
            abi.encodeWithSelector(SupersededCommitRegistry.SupersessionGenerationOverflow.selector, type(uint16).max)
        );
        registry.recordSupersession(oldCommit, newCommit, type(uint16).max, govRef);
    }

    function test_correctionAppendsAndHistoricalCheckpointPreservesRejectedEdge() external {
        vm.prank(timelock);
        registry.recordSupersession(oldCommit, newCommit, 1, govRef);
        uint64 firstBlock = uint64(block.number);
        bytes32 rejected = helpers.computeSupersededCommitLookup(oldCommit, 1);
        bytes32 corrected = keccak256("corrected");

        uint64 latestBlock = firstBlock + 10;
        vm.roll(latestBlock);
        vm.prank(timelock);
        registry.recordSupersessionCorrection(oldCommit, rejected, corrected, keccak256("gov-2"));

        assertEq(registry.lineageLength(oldCommit), 2);
        SupersededCommitRegistry.SupersessionEntry memory historical = registry.lineageCheckpoint(oldCommit, firstBlock);
        assertFalse(historical.correction);
        assertEq(historical.lookupHash, rejected);

        SupersededCommitRegistry.SupersessionEntry memory latest = registry.lineageCheckpoint(oldCommit, latestBlock);
        assertTrue(latest.correction);
        assertEq(latest.correctedLookupHash, corrected);
    }

    function test_successorOfAtHistoricalLookup() external {
        vm.prank(timelock);
        registry.recordSupersession(oldCommit, newCommit, 1, govRef);
        uint64 firstBlock = uint64(block.number);

        uint64 secondBlock = firstBlock + 10;
        vm.roll(secondBlock);
        vm.prank(timelock);
        registry.recordSupersession(oldCommit, keccak256("new-2"), 2, govRef);

        (bytes32 successor, uint16 generation) = registry.successorOfAt(oldCommit, firstBlock);
        assertEq(successor, newCommit);
        assertEq(generation, 1);
    }
}
