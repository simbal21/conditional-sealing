// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { RegistryUnauthorized } from "../../src/registries/PluginHashRegistry.sol";
import { OracleRegistry } from "../../src/registries/OracleRegistry.sol";

import { RegistryTestBase } from "./_HistoricalLookup.t.sol";

contract OracleRegistryTest is RegistryTestBase {
    event EntryAdded(bytes32 indexed id, uint64 effectiveBlock);

    function setUp() public {
        _setRegistryBaseUp();
    }

    function test_initialization_RoleGrantsWithoutOracleSubmitter() external {
        OracleRegistry registry = _deployOracle();
        assertTrue(registry.hasRole(Roles.DEFAULT_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.REGISTRY_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.SECURITY_COUNCIL_ROLE, securityCouncil));
        assertFalse(registry.hasRole(Roles.ORACLE_SUBMITTER_ROLE, timelock));
    }

    function test_addOracle_RoleDeniedAndUnknownCustomError() external {
        OracleRegistry registry = _deployOracle();
        OracleRegistry.OracleEntry memory entry = _oracleEntry(false);
        bytes32 id = registry.computeOracleId(entry.oraclePubkeyOrAddress);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RegistryUnauthorized.selector, Roles.REGISTRY_ADMIN_ROLE, stranger));
        registry.addOracle(id, entry);

        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryUnknown.selector, id));
        registry.getOracleAt(id, uint64(block.number));
    }

    function test_addOracle_EmitsAndTypedAccessorMatchesEncodedEntry() external {
        OracleRegistry registry = _deployOracle();
        OracleRegistry.OracleEntry memory entry = _oracleEntry(false);
        bytes32 id = registry.computeOracleId(entry.oraclePubkeyOrAddress);

        vm.expectEmit(true, false, false, true);
        emit EntryAdded(id, entry.effectiveBlock);
        vm.prank(timelock);
        registry.addOracle(id, entry);

        OracleRegistry.OracleEntry memory got = registry.getOracleAt(id, uint64(block.number));
        assertEq(got.schemaId, entry.schemaId);
        assertEq(registry.getEntry(id), abi.encode(got));
    }

    function test_pause_UUPS_AndDeprecationLifecycle() external {
        OracleRegistry registry = _deployOracle();
        OracleRegistry.OracleEntry memory nonCanonical = _oracleEntry(false);
        bytes32 nonCanonicalId = registry.computeOracleId(nonCanonical.oraclePubkeyOrAddress);
        vm.prank(timelock);
        registry.addOracle(nonCanonicalId, nonCanonical);

        vm.roll(block.number + 1);
        OracleRegistry.OracleEntry memory canonical = _oracleEntry(true);
        canonical.oraclePubkeyOrAddress = bytes("oracle-canonical");
        bytes32 canonicalId = registry.computeOracleId(canonical.oraclePubkeyOrAddress);
        vm.prank(timelock);
        registry.addOracle(canonicalId, canonical);

        _assertRegistryPauseSurface(registry);
        _assertNonCanonicalDeprecationLifecycle(registry, nonCanonicalId);
        _assertCanonicalDeprecationRequiresExpeditedTimelock(registry, canonicalId);
    }

    function test_upgrade_ByNonTimelockReverts() external {
        OracleRegistry implementation = new OracleRegistry();
        bytes memory init =
            abi.encodeCall(OracleRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser));
        address proxy = _proxy(address(implementation), init);
        OracleRegistry newImplementation = new OracleRegistry();
        _expectUnauthorizedUpgrade(proxy, address(newImplementation));
    }
}
