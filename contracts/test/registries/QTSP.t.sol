// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { RegistryUnauthorized } from "../../src/registries/PluginHashRegistry.sol";
import { QTSPRegistry } from "../../src/registries/QTSPRegistry.sol";

import { RegistryTestBase } from "./_HistoricalLookup.t.sol";

contract QTSPRegistryTest is RegistryTestBase {
    event EntryAdded(bytes32 indexed id, uint64 effectiveBlock);

    function setUp() public {
        _setRegistryBaseUp();
    }

    function test_initialization_RoleGrants() external {
        QTSPRegistry registry = _deployQTSP();
        assertTrue(registry.hasRole(Roles.DEFAULT_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.REGISTRY_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.SECURITY_COUNCIL_ROLE, securityCouncil));
        assertTrue(registry.hasRole(Roles.PAUSER_ROLE, pauser));
    }

    function test_addQTSP_RoleDeniedAndUnknownCustomError() external {
        QTSPRegistry registry = _deployQTSP();
        bytes32 id = keccak256("qtsp-ref");

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RegistryUnauthorized.selector, Roles.REGISTRY_ADMIN_ROLE, stranger));
        registry.addQTSP(id, _qtspEntry(false));

        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryUnknown.selector, id));
        registry.getQTSPAt(id, uint64(block.number));
    }

    function test_addQTSP_EmitsAndTypedAccessorMatchesEncodedEntry() external {
        QTSPRegistry registry = _deployQTSP();
        bytes32 id = keccak256("qtsp-ref");
        QTSPRegistry.QTSPEntry memory entry = _qtspEntry(false);

        vm.expectEmit(true, false, false, true);
        emit EntryAdded(id, entry.effectiveBlock);
        vm.prank(timelock);
        registry.addQTSP(id, entry);

        QTSPRegistry.QTSPEntry memory got = registry.getQTSPAt(id, uint64(block.number));
        assertEq(got.qtspRootPubkeyHash, entry.qtspRootPubkeyHash);
        assertEq(registry.getEntry(id), abi.encode(got));
    }

    function test_pause_UUPS_AndDeprecationLifecycle() external {
        QTSPRegistry registry = _deployQTSP();
        bytes32 nonCanonicalId = keccak256("qtsp-noncanonical");
        vm.prank(timelock);
        registry.addQTSP(nonCanonicalId, _qtspEntry(false));

        vm.roll(block.number + 1);
        bytes32 canonicalId = keccak256("qtsp-canonical");
        vm.prank(timelock);
        registry.addQTSP(canonicalId, _qtspEntry(true));

        _assertRegistryPauseSurface(registry);
        _assertNonCanonicalDeprecationLifecycle(registry, nonCanonicalId);
        _assertCanonicalDeprecationRequiresExpeditedTimelock(registry, canonicalId);
    }

    function test_upgrade_ByNonTimelockReverts() external {
        QTSPRegistry implementation = new QTSPRegistry();
        bytes memory init =
            abi.encodeCall(QTSPRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser));
        address proxy = _proxy(address(implementation), init);
        QTSPRegistry newImplementation = new QTSPRegistry();
        _expectUnauthorizedUpgrade(proxy, address(newImplementation));
    }
}
