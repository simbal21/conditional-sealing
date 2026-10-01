// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { RegistryUnauthorized } from "../../src/registries/PluginHashRegistry.sol";
import { DSLVersionRegistry } from "../../src/registries/DSLVersionRegistry.sol";

import { RegistryTestBase } from "./_HistoricalLookup.t.sol";

contract DSLVersionRegistryTest is RegistryTestBase {
    event EntryAdded(bytes32 indexed id, uint64 effectiveBlock);

    function setUp() public {
        _setRegistryBaseUp();
    }

    function test_initialization_RoleGrants() external {
        DSLVersionRegistry registry = _deployDSL();
        assertTrue(registry.hasRole(Roles.DEFAULT_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.REGISTRY_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.SECURITY_COUNCIL_ROLE, securityCouncil));
        assertTrue(registry.hasRole(Roles.PAUSER_ROLE, pauser));
    }

    function test_addDSLVersion_RoleDeniedAndUnknownCustomError() external {
        DSLVersionRegistry registry = _deployDSL();
        bytes32 id = keccak256("dsl-ref");

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RegistryUnauthorized.selector, Roles.REGISTRY_ADMIN_ROLE, stranger));
        registry.addDSLVersion(id, _dslEntry(false));

        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryUnknown.selector, id));
        registry.getDSLVersionAt(id, uint64(block.number));
    }

    function test_addDSLVersion_EmitsAndTypedAccessorMatchesEncodedEntry() external {
        DSLVersionRegistry registry = _deployDSL();
        bytes32 id = keccak256("dsl-ref");
        DSLVersionRegistry.DSLVersionEntry memory entry = _dslEntry(false);

        vm.expectEmit(true, false, false, true);
        emit EntryAdded(id, entry.effectiveBlock);
        vm.prank(timelock);
        registry.addDSLVersion(id, entry);

        DSLVersionRegistry.DSLVersionEntry memory got = registry.getDSLVersionAt(id, uint64(block.number));
        assertEq(got.interpreter, entry.interpreter);
        assertEq(registry.getEntry(id), abi.encode(got));
    }

    function test_pause_UUPS_AndDeprecationLifecycle() external {
        DSLVersionRegistry registry = _deployDSL();
        bytes32 nonCanonicalId = keccak256("dsl-noncanonical");
        vm.prank(timelock);
        registry.addDSLVersion(nonCanonicalId, _dslEntry(false));

        vm.roll(block.number + 1);
        bytes32 canonicalId = keccak256("dsl-canonical");
        vm.prank(timelock);
        registry.addDSLVersion(canonicalId, _dslEntry(true));

        _assertRegistryPauseSurface(registry);
        _assertNonCanonicalDeprecationLifecycle(registry, nonCanonicalId);
        _assertCanonicalDeprecationRequiresExpeditedTimelock(registry, canonicalId);
    }

    function test_upgrade_ByNonTimelockReverts() external {
        DSLVersionRegistry implementation = new DSLVersionRegistry();
        bytes memory init =
            abi.encodeCall(DSLVersionRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser));
        address proxy = _proxy(address(implementation), init);
        DSLVersionRegistry newImplementation = new DSLVersionRegistry();
        _expectUnauthorizedUpgrade(proxy, address(newImplementation));
    }
}
