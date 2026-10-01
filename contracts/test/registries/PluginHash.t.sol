// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { RegistryUnauthorized } from "../../src/registries/PluginHashRegistry.sol";
import { PluginHashRegistry } from "../../src/registries/PluginHashRegistry.sol";

import { RegistryTestBase } from "./_HistoricalLookup.t.sol";

contract PluginHashRegistryTest is RegistryTestBase {
    event EntryAdded(bytes32 indexed id, uint64 effectiveBlock);

    function setUp() public {
        _setRegistryBaseUp();
    }

    function test_initialization_RoleGrants() external {
        PluginHashRegistry registry = _deployPlugin();
        assertTrue(registry.hasRole(Roles.DEFAULT_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.UPGRADER_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.REGISTRY_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.SECURITY_COUNCIL_ROLE, securityCouncil));
        assertTrue(registry.hasRole(Roles.EMERGENCY_GOVERNANCE_ROLE, emergencyGovernance));
        assertTrue(registry.hasRole(Roles.PAUSER_ROLE, pauser));
    }

    function test_addPlugin_RoleDeniedAndUnknownCustomError() external {
        PluginHashRegistry registry = _deployPlugin();
        PluginHashRegistry.PluginEntry memory entry = _pluginEntry(false);
        bytes32 id = helper.computePluginVersionDigest(entry.canonicalBinaryHash);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RegistryUnauthorized.selector, Roles.REGISTRY_ADMIN_ROLE, stranger));
        registry.addPlugin(id, entry);

        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryUnknown.selector, id));
        registry.getPluginAt(id, uint64(block.number));
    }

    function test_addPlugin_EmitsAndTypedAccessorMatchesEncodedEntry() external {
        PluginHashRegistry registry = _deployPlugin();
        PluginHashRegistry.PluginEntry memory entry = _pluginEntry(false);
        bytes32 id = helper.computePluginVersionDigest(entry.canonicalBinaryHash);

        vm.expectEmit(true, false, false, true);
        emit EntryAdded(id, entry.effectiveBlock);
        vm.prank(timelock);
        registry.addPlugin(id, entry);

        PluginHashRegistry.PluginEntry memory got = registry.getPluginAt(id, uint64(block.number));
        assertEq(got.canonicalBinaryHash, entry.canonicalBinaryHash);
        assertFalse(got.deprecationFlag.deprecated);
        assertEq(registry.getEntry(id), abi.encode(got));
    }

    function test_pause_UUPS_AndDeprecationLifecycle() external {
        PluginHashRegistry registry = _deployPlugin();
        PluginHashRegistry.PluginEntry memory nonCanonical = _pluginEntry(false);
        bytes32 nonCanonicalId = helper.computePluginVersionDigest(nonCanonical.canonicalBinaryHash);
        vm.prank(timelock);
        registry.addPlugin(nonCanonicalId, nonCanonical);

        vm.roll(block.number + 1);
        PluginHashRegistry.PluginEntry memory canonical = _pluginEntry(true);
        canonical.canonicalBinaryHash = keccak256("plugin.bin.canonical");
        bytes32 canonicalId = helper.computePluginVersionDigest(canonical.canonicalBinaryHash);
        vm.prank(timelock);
        registry.addPlugin(canonicalId, canonical);

        _assertRegistryPauseSurface(registry);
        _assertNonCanonicalDeprecationLifecycle(registry, nonCanonicalId);
        _assertCanonicalDeprecationRequiresExpeditedTimelock(registry, canonicalId);
    }

    function test_upgrade_ByNonTimelockReverts() external {
        PluginHashRegistry implementation = new PluginHashRegistry();
        bytes memory init = abi.encodeCall(
            PluginHashRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser, address(helper))
        );
        address proxy = _proxy(address(implementation), init);
        PluginHashRegistry newImplementation = new PluginHashRegistry();
        _expectUnauthorizedUpgrade(proxy, address(newImplementation));
    }
}
