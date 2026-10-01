// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { RegistryUnauthorized } from "../../src/registries/PluginHashRegistry.sol";
import { G4AuthorityRegistry } from "../../src/registries/G4AuthorityRegistry.sol";

import { RegistryTestBase } from "./_HistoricalLookup.t.sol";

contract G4AuthorityRegistryTest is RegistryTestBase {
    event EntryAdded(bytes32 indexed id, uint64 effectiveBlock);

    function setUp() public {
        _setRegistryBaseUp();
    }

    function test_initialization_RoleGrantsIncludingOperator() external {
        G4AuthorityRegistry registry = _deployG4();
        assertTrue(registry.hasRole(Roles.DEFAULT_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.UPGRADER_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.REGISTRY_ADMIN_ROLE, timelock));
        assertTrue(registry.hasRole(Roles.SECURITY_COUNCIL_ROLE, securityCouncil));
        assertTrue(registry.hasRole(Roles.PAUSER_ROLE, pauser));
        assertTrue(registry.hasRole(Roles.OPERATOR_ROLE, g4Operator));
    }

    function test_addG4Authority_RoleDeniedAndUnknownCustomError() external {
        G4AuthorityRegistry registry = _deployG4();
        G4AuthorityRegistry.G4AuthorityEntry memory entry = _g4Entry(false);
        bytes32 id = helper.computeG4AuthorityRef(entry.authorityPubkey);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(RegistryUnauthorized.selector, Roles.REGISTRY_ADMIN_ROLE, stranger));
        registry.addG4Authority(id, entry);

        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryUnknown.selector, id));
        registry.getG4AuthorityAt(id, uint64(block.number));
    }

    function test_addG4Authority_EmitsAndSupportsPhaseOneAndTwoHistory() external {
        G4AuthorityRegistry registry = _deployG4();
        G4AuthorityRegistry.G4AuthorityEntry memory phase1 = _g4Entry(false);
        phase1.phase = 1;
        bytes32 phase1Id = helper.computeG4AuthorityRef(phase1.authorityPubkey);

        vm.expectEmit(true, false, false, true);
        emit EntryAdded(phase1Id, phase1.effectiveBlock);
        vm.prank(timelock);
        registry.addG4Authority(phase1Id, phase1);
        uint64 phase1Block = uint64(block.number);

        vm.roll(block.number + 1);
        G4AuthorityRegistry.G4AuthorityEntry memory phase2 = _g4Entry(false);
        phase2.authorityPubkey = bytes("g4-authority-pubkey-phase2");
        bytes32 phase2Id = helper.computeG4AuthorityRef(phase2.authorityPubkey);
        vm.prank(timelock);
        registry.addG4Authority(phase2Id, phase2);
        uint64 phase2Block = phase1Block + 1;

        assertEq(registry.getG4AuthorityAt(phase1Id, phase1Block).phase, 1, "phase1 historical");
        assertEq(registry.getG4AuthorityAt(phase2Id, phase2Block).phase, 2, "phase2 current");
    }

    function test_pause_UUPS_AndDeprecationLifecycle() external {
        G4AuthorityRegistry registry = _deployG4();
        G4AuthorityRegistry.G4AuthorityEntry memory nonCanonical = _g4Entry(false);
        bytes32 nonCanonicalId = helper.computeG4AuthorityRef(nonCanonical.authorityPubkey);
        vm.prank(timelock);
        registry.addG4Authority(nonCanonicalId, nonCanonical);

        vm.roll(block.number + 1);
        G4AuthorityRegistry.G4AuthorityEntry memory canonical = _g4Entry(true);
        canonical.authorityPubkey = bytes("g4-authority-canonical");
        bytes32 canonicalId = helper.computeG4AuthorityRef(canonical.authorityPubkey);
        vm.prank(timelock);
        registry.addG4Authority(canonicalId, canonical);

        _assertRegistryPauseSurface(registry);
        _assertNonCanonicalDeprecationLifecycle(registry, nonCanonicalId);
        _assertCanonicalDeprecationRequiresExpeditedTimelock(registry, canonicalId);
    }

    function test_upgrade_ByNonTimelockReverts() external {
        G4AuthorityRegistry implementation = new G4AuthorityRegistry();
        bytes memory init = abi.encodeCall(
            G4AuthorityRegistry.initialize,
            (timelock, securityCouncil, emergencyGovernance, pauser, g4Operator, address(helper))
        );
        address proxy = _proxy(address(implementation), init);
        G4AuthorityRegistry newImplementation = new G4AuthorityRegistry();
        _expectUnauthorizedUpgrade(proxy, address(newImplementation));
    }
}
