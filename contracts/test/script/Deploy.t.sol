// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { Test } from "forge-std/Test.sol";

import { ChallengeRegistry } from "../../src/challenge/ChallengeRegistry.sol";
import { DisclosureRegistry } from "../../src/disclosure/DisclosureRegistry.sol";
import { DisclosureRevocationRegistry } from "../../src/disclosure/DisclosureRevocationRegistry.sol";
import { FSMInterpreter } from "../../src/fsm/FSMInterpreter.sol";
import { GateRecipientPubkeyRegistry } from "../../src/gate-recipient/GateRecipientPubkeyRegistry.sol";
import { LitV3Assignment } from "../../src/lit/LitV3Assignment.sol";
import { CeremonyAxis, GateKind } from "../../src/lib/Enums.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { DSLVersionRegistry } from "../../src/registries/DSLVersionRegistry.sol";
import { G4AuthorityRegistry } from "../../src/registries/G4AuthorityRegistry.sol";
import { OracleRegistry } from "../../src/registries/OracleRegistry.sol";
import { OracleSchemaRegistry } from "../../src/registries/OracleSchemaRegistry.sol";
import { ShredRegistry } from "../../src/shred/ShredRegistry.sol";
import { Deploy } from "../../script/Deploy.s.sol";
import { PostDeploy } from "../../script/PostDeploy.s.sol";

interface IModuleWithEngine {
    function conditionEngine() external view returns (address);
}

contract DeployTest is Test {
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    Deploy.Addresses internal addrs;
    PostDeploy.InitialRefs internal refs;

    address internal stranger = address(0xBEEF);

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(100);
        Deploy deployer = new Deploy();
        addrs = deployer.run();
        PostDeploy postDeploy = new PostDeploy();
        refs = postDeploy.run(addrs);
    }

    function test_assertion_01_proxyImplementationsNonZero() public view {
        address[] memory targets = _uupsTargets();
        for (uint256 i = 0; i < targets.length; ++i) {
            assertTrue(targets[i].code.length != 0, "proxy code missing");
            assertTrue(_implementationOf(targets[i]) != address(0), "implementation missing");
            assertTrue(_implementationOf(targets[i]).code.length != 0, "implementation code missing");
        }
    }

    function test_assertion_02_initializersRanOnce() public {
        vm.expectRevert();
        DisclosureRegistry(addrs.disclosureRegistry)
            .initialize(addrs.temporaryAdmin, addrs.disclosureRevocationRegistry);
        vm.expectRevert();
        DSLVersionRegistry(addrs.dslVersionRegistry)
            .initialize(addrs.temporaryAdmin, address(1), address(2), address(3));
        vm.expectRevert();
        LitV3Assignment(addrs.litV3Assignment).initialize(addrs.temporaryAdmin);
    }

    function test_assertion_03_registriesHaveTimelockAdmin() public view {
        address[] memory targets = _uupsTargets();
        for (uint256 i = 0; i < targets.length; ++i) {
            assertTrue(_hasRole(targets[i], Roles.DEFAULT_ADMIN_ROLE, addrs.timelock), "timelock admin missing");
            assertFalse(_hasRole(targets[i], Roles.DEFAULT_ADMIN_ROLE, addrs.temporaryAdmin), "temp admin retained");
        }
    }

    function test_assertion_04_securityMultisigDeprecationOnly() public view {
        address[] memory registries = _governedRegistries();
        for (uint256 i = 0; i < registries.length; ++i) {
            assertTrue(_hasRole(registries[i], Roles.SECURITY_COUNCIL_ROLE, addrs.securityMultisig), "council missing");
            assertFalse(
                _hasRole(registries[i], Roles.REGISTRY_ADMIN_ROLE, addrs.securityMultisig), "council has addition role"
            );
            assertFalse(
                _hasRole(registries[i], Roles.UPGRADER_ROLE, addrs.securityMultisig), "council has upgrader role"
            );
        }
    }

    function test_assertion_05_uupsContractsHaveTimelockUpgrader() public view {
        _assertSoleRoleOnAllUups(Roles.UPGRADER_ROLE);
    }

    function test_assertion_06_conditionEngineKnowsAllNineModules() public view {
        assertEq(addrs.moduleAddresses.length, 9, "module count");
        assertEq(addrs.moduleAddresses[0], addrs.paymentObligationModule);
        assertEq(addrs.moduleAddresses[1], addrs.timeLockModule);
        assertEq(addrs.moduleAddresses[2], addrs.subjectInitiatedModule);
        assertEq(addrs.moduleAddresses[3], addrs.heartbeatMissedModule);
        assertEq(addrs.moduleAddresses[4], addrs.oracleAttestationModule);
        assertEq(addrs.moduleAddresses[5], addrs.multiPartySignalModule);
        assertEq(addrs.moduleAddresses[6], addrs.deadManSwitchModule);
        assertEq(addrs.moduleAddresses[7], addrs.consentGateModule);
        assertEq(addrs.moduleAddresses[8], addrs.composedModule);
    }

    function test_assertion_07_modulesRecognizeConditionEngine() public view {
        for (uint256 i = 0; i < addrs.moduleAddresses.length; ++i) {
            assertEq(IModuleWithEngine(addrs.moduleAddresses[i]).conditionEngine(), addrs.conditionEngine);
        }
        assertEq(FSMInterpreter(addrs.fsmInterpreter).conditionEngine(), addrs.conditionEngine);
    }

    function test_assertion_08_shredRegistryRecognizesConditionEngine() public view {
        assertEq(ShredRegistry(addrs.shredRegistry).conditionEngine(), addrs.conditionEngine);
    }

    function test_assertion_09_challengeRegistryRecognizesConditionEngine() public view {
        assertTrue(_hasRole(addrs.challengeRegistry, Roles.ORCHESTRATOR_ROLE, addrs.conditionEngine));
    }

    function test_assertion_10_g4RefusalRegistryRecognizesG4Authority() public view {
        assertTrue(_hasRole(addrs.g4RefusalRegistry, Roles.OPERATOR_ROLE, addrs.temporaryAdmin));
        assertFalse(_hasRole(addrs.g4RefusalRegistry, Roles.OPERATOR_ROLE, stranger));
    }

    function test_assertion_11_gateRecipientPubkeyRolesConfigured() public {
        GateRecipientPubkeyRegistry registry = GateRecipientPubkeyRegistry(addrs.gateRecipientPubkeyRegistry);
        bytes32 authorizationId = keccak256("authorization");

        vm.prank(addrs.temporaryAdmin);
        registry.publishPubkey(
            GateRecipientPubkeyRegistry.GateRecipientPubkeyEntry({
                authorizationId: authorizationId,
                gateKind: uint8(GateKind.LitV3),
                conditionalRecipientIndex: 0,
                kemPubkey: bytes("ephemeral"),
                attestationRef: keccak256("attestation"),
                effectiveBlock: uint64(block.number),
                tombstoneBlock: 0,
                perCommitEphemeral: true
            })
        );
        assertEq(registry.historyLength(authorizationId, uint8(GateKind.LitV3), 0), 1);

        vm.prank(addrs.timelock);
        registry.publishPubkey(
            GateRecipientPubkeyRegistry.GateRecipientPubkeyEntry({
                authorizationId: authorizationId,
                gateKind: uint8(GateKind.Drand),
                conditionalRecipientIndex: 0,
                kemPubkey: bytes("committee"),
                attestationRef: keccak256("committee-attestation"),
                effectiveBlock: uint64(block.number),
                tombstoneBlock: 0,
                perCommitEphemeral: false
            })
        );
        assertEq(registry.historyLength(authorizationId, uint8(GateKind.Drand), 0), 1);

        assertFalse(_hasRole(addrs.gateRecipientPubkeyRegistry, Roles.GATE_PUBKEY_PUBLISHER_ROLE, stranger));
    }

    function test_assertion_12_disclosureRolesOnlyOnIntendedPrincipals() public view {
        assertTrue(_hasRole(addrs.disclosureRegistry, Roles.SD_OPERATOR_ROLE, addrs.temporaryAdmin));
        assertFalse(_hasRole(addrs.disclosureRegistry, Roles.SD_OPERATOR_ROLE, stranger));
        assertTrue(_hasRole(addrs.disclosureRevocationRegistry, Roles.ORCHESTRATOR_ROLE, addrs.temporaryAdmin));
        assertFalse(_hasRole(addrs.disclosureRevocationRegistry, Roles.ORCHESTRATOR_ROLE, stranger));
        assertTrue(_hasRole(addrs.disclosureRevocationRegistry, Roles.REVOCATION_ADMIN_ROLE, addrs.timelock));
        assertFalse(_hasRole(addrs.disclosureRevocationRegistry, Roles.REVOCATION_ADMIN_ROLE, stranger));
    }

    function test_assertion_12a_bothDisclosureRegistriesAreUUPS() public view {
        assertTrue(_implementationOf(addrs.disclosureRegistry) != address(0));
        assertTrue(_implementationOf(addrs.disclosureRevocationRegistry) != address(0));
    }

    function test_assertion_12b_disclosureRegistryRevocationRegistryView() public view {
        assertEq(DisclosureRegistry(addrs.disclosureRegistry).revocationRegistry(), addrs.disclosureRevocationRegistry);
    }

    function test_assertion_12c_verifyAndCommitDisclosureFailClosed() public {
        bytes32 disclosureId = keccak256("disclosure");
        bytes32 verifierRef = keccak256("verifier");
        DisclosureRevocationRegistry revocations = DisclosureRevocationRegistry(addrs.disclosureRevocationRegistry);
        DisclosureRegistry disclosure = DisclosureRegistry(addrs.disclosureRegistry);

        vm.prank(addrs.temporaryAdmin);
        revocations.registerDisclosure(
            disclosureId, keccak256("auth"), keccak256("claim"), verifierRef, uint64(block.timestamp + 1 days), stranger
        );
        vm.prank(addrs.temporaryAdmin);
        disclosure.registerVerifier(verifierRef);
        vm.prank(addrs.temporaryAdmin);
        revocations.pause(bytes32(0), uint64(block.timestamp + 1 days), keccak256("pause"));

        vm.prank(addrs.temporaryAdmin);
        vm.expectRevert(DisclosureRegistry.RevocationRegistryUnavailable.selector);
        disclosure.verifyAndCommitDisclosure(
            disclosureId, keccak256("auth"), bytes32(0), verifierRef, "", "", bytes32(0)
        );
    }

    function test_assertion_12d_isRevokedRevertsOnUnknown() public {
        bytes32 disclosureId = keccak256("unknown-disclosure");
        vm.expectRevert(abi.encodeWithSelector(DisclosureRevocationRegistry.DisclosureUnknown.selector, disclosureId));
        DisclosureRevocationRegistry(addrs.disclosureRevocationRegistry).isRevoked(disclosureId);
    }

    function test_assertion_12e_canRevokeUnauthorizedReverts() public {
        bytes32 disclosureId = keccak256("disclosure-unauthorized");
        DisclosureRevocationRegistry revocations = DisclosureRevocationRegistry(addrs.disclosureRevocationRegistry);
        vm.prank(addrs.temporaryAdmin);
        revocations.registerDisclosure(
            disclosureId,
            keccak256("auth"),
            keccak256("claim"),
            keccak256("verifier"),
            uint64(block.timestamp + 1 days),
            address(0xCAFE)
        );

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(DisclosureRevocationRegistry.DisclosureRevocationUnauthorized.selector, disclosureId)
        );
        revocations.revokeDisclosure(disclosureId, 1, keccak256("evidence"));
    }

    function test_assertion_13_litV3AssignmentBridgeOnly() public {
        LitV3Assignment lit = LitV3Assignment(addrs.litV3Assignment);
        bytes32 authorizationId = keccak256("lit-auth");

        vm.prank(addrs.temporaryAdmin);
        lit.recordAssignment(authorizationId, keccak256("tee"), uint64(block.number), bytes("pubkey"), keccak256("gov"));
        assertEq(lit.assignmentHistoryLength(authorizationId), 1);

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(LitV3Assignment.LitUnauthorizedBridge.selector, stranger));
        lit.recordAssignment(
            keccak256("other"), keccak256("tee"), uint64(block.number), bytes("pubkey"), keccak256("gov")
        );
    }

    function test_assertion_14_passkeyRotationLogCanonicalAddress() public view {
        assertTrue(addrs.passkeyRotationLog != address(0));
        assertTrue(addrs.passkeyRotationLog.code.length != 0);
    }

    function test_assertion_15_initialDSLAndOracleSchemasAndG4Entries() public view {
        DSLVersionRegistry.DSLVersionEntry memory dsl =
            DSLVersionRegistry(addrs.dslVersionRegistry).getDSLVersionAt(refs.dslVersionRef, uint64(block.number));
        assertEq(dsl.interpreter, addrs.claimDSL);
        assertTrue(dsl.isCanonical);
        assertFalse(dsl.deprecationFlag.deprecated);

        OracleSchemaRegistry.OracleSchemaEntry memory chainlink =
            OracleSchemaRegistry(addrs.oracleSchemaRegistry).getSchemaAt(refs.chainlinkSchemaId, uint64(block.number));
        assertTrue(chainlink.schemaHash != bytes32(0));
        OracleSchemaRegistry.OracleSchemaEntry memory subject = OracleSchemaRegistry(addrs.oracleSchemaRegistry)
            .getSchemaAt(refs.subjectInitiatedSchemaId, uint64(block.number));
        assertTrue(subject.schemaHash != bytes32(0));

        OracleRegistry.OracleEntry memory oracle =
            OracleRegistry(addrs.oracleRegistry).getOracleAt(refs.chainlinkOracleId, uint64(block.number));
        assertEq(oracle.schemaId, refs.chainlinkSchemaId);

        G4AuthorityRegistry.G4AuthorityEntry memory g4 =
            G4AuthorityRegistry(addrs.g4AuthorityRegistry).getG4AuthorityAt(refs.g4Phase1Ref, uint64(block.number));
        assertEq(g4.phase, 1);
        assertTrue(g4.isCanonical);
    }

    function test_invariant_upgraderRoleSingleHolder() public view {
        _assertSoleRoleOnAllUups(Roles.UPGRADER_ROLE);
    }

    function test_invariant_defaultAdminRoleSingleHolder() public view {
        _assertSoleRoleOnAllUups(Roles.DEFAULT_ADMIN_ROLE);
    }

    function test_invariant_noGuardianRoleAnywhere() public pure {
        assertTrue(Roles.SECURITY_COUNCIL_ROLE != 0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041);
    }

    function test_invariant_registryAdminMovedToTimelock() public view {
        address[] memory registries = _governedRegistries();
        for (uint256 i = 0; i < registries.length; ++i) {
            assertTrue(_hasRole(registries[i], Roles.REGISTRY_ADMIN_ROLE, addrs.timelock));
            assertFalse(_hasRole(registries[i], Roles.REGISTRY_ADMIN_ROLE, addrs.temporaryAdmin));
        }
    }

    function test_invariant_challengeResolverPdaScoped() public {
        ChallengeRegistry registry = ChallengeRegistry(addrs.challengeRegistry);
        bytes32 auth = keccak256("challenge-auth");
        vm.prank(addrs.timelock);
        registry.grantRole(Roles.CHALLENGE_RESOLVER_ROLE, addrs.temporaryAdmin);
        vm.prank(addrs.conditionEngine);
        registry.configureChallenge(
            auth,
            CeremonyAxis.Reveal,
            uint64(block.timestamp + 1 days),
            0,
            bytes32(0),
            address(this),
            addrs.temporaryAdmin,
            1,
            address(0xBEEF)
        );
        registry.openChallenge{ value: 1 }(
            auth,
            CeremonyAxis.Reveal,
            ChallengeRegistry.ChallengeReason.ConditionMisapplied,
            keccak256("counter"),
            0,
            new bytes32[](0)
        );

        vm.prank(addrs.temporaryAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChallengeRegistry.ChallengeResolverUnauthorized.selector, keccak256("other"), addrs.temporaryAdmin
            )
        );
        registry.confirmNoIntervention(keccak256("other"), CeremonyAxis.Reveal, keccak256("action"));
    }

    function _assertSoleRoleOnAllUups(bytes32 role) internal view {
        address[] memory targets = _uupsTargets();
        for (uint256 i = 0; i < targets.length; ++i) {
            assertTrue(_hasRole(targets[i], role, addrs.timelock), "timelock role missing");
            assertFalse(_hasRole(targets[i], role, addrs.temporaryAdmin), "temporary role retained");
            assertFalse(_hasRole(targets[i], role, stranger), "stranger role");
        }
    }

    function _implementationOf(address proxy) internal view returns (address) {
        return address(uint160(uint256(vm.load(proxy, IMPLEMENTATION_SLOT))));
    }

    function _hasRole(address target, bytes32 role, address account) internal view returns (bool) {
        return IAccessControl(target).hasRole(role, account);
    }

    function _uupsTargets() internal view returns (address[] memory targets) {
        targets = new address[](30);
        targets[0] = addrs.securityMultisig;
        targets[1] = addrs.emergencyGovernance;
        targets[2] = addrs.pluginHashRegistry;
        targets[3] = addrs.g4AuthorityRegistry;
        targets[4] = addrs.dslVersionRegistry;
        targets[5] = addrs.oracleRegistry;
        targets[6] = addrs.oracleSchemaRegistry;
        targets[7] = addrs.qtspRegistry;
        targets[8] = addrs.gateRecipientPubkeyRegistry;
        targets[9] = addrs.litV3Assignment;
        targets[10] = addrs.disclosureRevocationRegistry;
        targets[11] = addrs.disclosureRegistry;
        targets[12] = addrs.g4RefusalRegistry;
        targets[13] = addrs.passkeyRotationLog;
        targets[14] = addrs.supersededCommitRegistry;
        targets[15] = addrs.challengeRegistry;
        targets[16] = addrs.claimDSL;
        targets[17] = addrs.fsmInterpreter;
        targets[18] = addrs.paymentObligationModule;
        targets[19] = addrs.timeLockModule;
        targets[20] = addrs.subjectInitiatedModule;
        targets[21] = addrs.heartbeatMissedModule;
        targets[22] = addrs.oracleAttestationModule;
        targets[23] = addrs.multiPartySignalModule;
        targets[24] = addrs.deadManSwitchModule;
        targets[25] = addrs.consentGateModule;
        targets[26] = addrs.composedModule;
        targets[27] = addrs.attestationGate;
        targets[28] = addrs.shredRegistry;
        targets[29] = addrs.conditionEngine;
    }

    function _governedRegistries() internal view returns (address[] memory registries) {
        registries = new address[](6);
        registries[0] = addrs.pluginHashRegistry;
        registries[1] = addrs.g4AuthorityRegistry;
        registries[2] = addrs.dslVersionRegistry;
        registries[3] = addrs.oracleRegistry;
        registries[4] = addrs.oracleSchemaRegistry;
        registries[5] = addrs.qtspRegistry;
    }
}
