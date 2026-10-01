// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { DisclosureRevocationRegistry } from "../../src/disclosure/DisclosureRevocationRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract DisclosureRevocationRegistryTest is Test {
    DisclosureRevocationRegistry internal registry;

    address internal timelock = address(0x5001);
    address internal orchestrator = address(0x5002);
    address internal admin = address(0x5003);
    address internal revoker = address(0x5004);
    address internal stranger = address(0x5005);

    bytes32 internal disclosureId = keccak256("disclosure");
    bytes32 internal auth = keccak256("auth");

    function setUp() public {
        registry = DisclosureRevocationRegistry(
            ProxyDeploy.deployProxy(
                address(new DisclosureRevocationRegistry()),
                abi.encodeCall(DisclosureRevocationRegistry.initialize, (timelock))
            )
        );
        vm.startPrank(timelock);
        registry.grantRole(Roles.ORCHESTRATOR_ROLE, orchestrator);
        registry.grantRole(Roles.REVOCATION_ADMIN_ROLE, admin);
        vm.stopPrank();
    }

    function test_isRevokedRevertsForUnknownDisclosure() external {
        vm.expectRevert(abi.encodeWithSelector(DisclosureRevocationRegistry.DisclosureUnknown.selector, disclosureId));
        registry.isRevoked(disclosureId);
    }

    function test_unauthorizedRevokerReverts() external {
        _register(disclosureId, revoker);
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(DisclosureRevocationRegistry.DisclosureRevocationUnauthorized.selector, disclosureId)
        );
        registry.revokeDisclosure(disclosureId, 1, keccak256("evidence"));
    }

    function test_authorizedRevokerIsImmutableAfterRegistration() external {
        _register(disclosureId, revoker);
        vm.prank(orchestrator);
        vm.expectRevert(
            abi.encodeWithSelector(DisclosureRevocationRegistry.DisclosureAlreadyRegistered.selector, disclosureId)
        );
        registry.registerDisclosure(disclosureId, auth, keccak256("claim2"), keccak256("verifier2"), 2, stranger);
        assertEq(registry.authorizedRevoker(disclosureId), revoker);
    }

    function test_globalAdminRevocationSucceeds() external {
        _register(disclosureId, revoker);
        vm.prank(admin);
        registry.revokeDisclosure(disclosureId, 2, keccak256("evidence"));
        assertTrue(registry.isRevoked(disclosureId));
    }

    function test_partnerAuthorizedRevokerSucceeds() external {
        _register(disclosureId, revoker);
        vm.prank(revoker);
        registry.revokeDisclosure(disclosureId, 3, keccak256("evidence"));
        assertTrue(registry.isRevoked(disclosureId));
    }

    function _register(bytes32 id, address authorizedRevoker) internal {
        vm.prank(orchestrator);
        registry.registerDisclosure(id, auth, keccak256("claim"), keccak256("verifier"), 10, authorizedRevoker);
    }
}
