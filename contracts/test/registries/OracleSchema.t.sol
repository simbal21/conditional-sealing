// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { RegistryUnauthorized } from "../../src/registries/PluginHashRegistry.sol";
import { OracleSchemaRegistry, OracleSchemaUnknown } from "../../src/registries/OracleSchemaRegistry.sol";

import { RegistryTestBase } from "./_HistoricalLookup.t.sol";

contract OracleSchemaRegistryTest is RegistryTestBase {
    event EntryAdded(bytes32 indexed id, uint64 effectiveBlock);
    event OracleSchemaAdded(
        bytes32 indexed schemaId,
        bytes32 schemaHash,
        bytes32 validExamplesHash,
        bytes32 invalidExamplesHash,
        uint64 effectiveBlock
    );

    function setUp() public {
        _setRegistryBaseUp();
    }

    function test_initialization_RoleGrants() external {
        OracleSchemaRegistry registry = _deploySchema();
        assertTrue(registry.hasRole(Roles.DEFAULT_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.REGISTRY_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.SECURITY_COUNCIL_ROLE, securityCouncil));
        assertTrue(registry.hasRole(Roles.PAUSER_ROLE, pauser));
    }

    function test_addSchema_RoleDeniedAndUnknownCustomErrors() external {
        OracleSchemaRegistry registry = _deploySchema();
        bytes32 id = keccak256("schema-id");

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RegistryUnauthorized.selector, Roles.REGISTRY_ADMIN_ROLE, stranger));
        registry.addSchema(id, _schemaEntry(false));

        vm.expectRevert(abi.encodeWithSelector(OracleSchemaUnknown.selector, id));
        registry.getSchema(id);

        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryUnknown.selector, id));
        registry.getEntryAt(id, uint64(block.number));
    }

    function test_addSchema_EmitsAndCurrentAndHistoricalAccessorsWork() external {
        OracleSchemaRegistry registry = _deploySchema();
        bytes32 id = keccak256("schema-id");
        OracleSchemaRegistry.OracleSchemaEntry memory entry = _schemaEntry(false);

        vm.expectEmit(true, false, false, true);
        emit EntryAdded(id, entry.effectiveBlock);
        vm.expectEmit(true, false, false, true);
        emit OracleSchemaAdded(
            id, entry.schemaHash, entry.validExamplesHash, entry.invalidExamplesHash, entry.effectiveBlock
        );
        vm.prank(timelock);
        registry.addSchema(id, entry);

        OracleSchemaRegistry.OracleSchemaEntry memory got = registry.getSchema(id);
        assertEq(got.schemaHash, entry.schemaHash);
        assertEq(registry.getSchemaAt(id, uint64(block.number)).schemaVersion, 1);
        assertEq(registry.getEntry(id), abi.encode(got));
    }

    function test_pause_UUPS_AndDeprecationLifecycle() external {
        OracleSchemaRegistry registry = _deploySchema();
        bytes32 nonCanonicalId = keccak256("schema-noncanonical");
        vm.prank(timelock);
        registry.addSchema(nonCanonicalId, _schemaEntry(false));

        vm.roll(block.number + 1);
        bytes32 canonicalId = keccak256("schema-canonical");
        vm.prank(timelock);
        registry.addSchema(canonicalId, _schemaEntry(true));

        _assertRegistryPauseSurface(registry);
        _assertNonCanonicalDeprecationLifecycle(registry, nonCanonicalId);
        _assertCanonicalDeprecationRequiresExpeditedTimelock(registry, canonicalId);
    }

    function test_upgrade_ByNonTimelockReverts() external {
        OracleSchemaRegistry implementation = new OracleSchemaRegistry();
        bytes memory init =
            abi.encodeCall(OracleSchemaRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser));
        address proxy = _proxy(address(implementation), init);
        OracleSchemaRegistry newImplementation = new OracleSchemaRegistry();
        _expectUnauthorizedUpgrade(proxy, address(newImplementation));
    }
}
