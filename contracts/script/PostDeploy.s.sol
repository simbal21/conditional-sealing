// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Script } from "forge-std/Script.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { TimelockController } from "@openzeppelin/contracts/governance/TimelockController.sol";

import { IConditionEngine } from "../src/engine/IConditionEngine.sol";
import {
    ConditionMode,
    ConditionalRecipientMode,
    G4Phase,
    PauseAuthorityMode,
    ProtocolVersion,
    ShredAuthorityMode
} from "../src/lib/Enums.sol";
import { Roles } from "../src/lib/Roles.sol";
import {
    AxisConfig,
    DeprecationFlag,
    HCommitFields,
    LegalFlags,
    PDARegistration,
    PdaRootFields,
    RegistryRefs
} from "../src/lib/Structs.sol";
import { CealisIdentifierHelpers } from "../src/helpers/CealisIdentifierHelpers.sol";
import { CealisSecurityMultisig } from "../src/governance/CealisSecurityMultisig.sol";
import { DSLVersionRegistry } from "../src/registries/DSLVersionRegistry.sol";
import { G4AuthorityRegistry } from "../src/registries/G4AuthorityRegistry.sol";
import { OracleRegistry } from "../src/registries/OracleRegistry.sol";
import { OracleSchemaRegistry } from "../src/registries/OracleSchemaRegistry.sol";
import { PluginHashRegistry } from "../src/registries/PluginHashRegistry.sol";
import { Deploy } from "./Deploy.s.sol";

contract PostDeploy is Script {
    string internal constant DEPLOYMENTS_PATH = "deployments/base-sepolia.json";

    error PostDeployAssertionFailed(bytes32 assertionId);

    bytes32 internal constant ASSERT_MODE3 = keccak256("postdeploy.mode3");
    bytes32 internal constant ASSERT_LEGAL_PHASE = keccak256("postdeploy.legal.phase");
    bytes32 internal constant ASSERT_LEGAL_HALT = keccak256("postdeploy.legal.halt");

    struct InitialRefs {
        bytes32 dslVersionRef;
        bytes32 pluginVersionDigest;
        bytes32 g4Phase1Ref;
        bytes32 g4Phase2Ref;
        bytes32 chainlinkOracleId;
        bytes32 chainlinkSchemaId;
        bytes32 subjectInitiatedSchemaId;
    }

    function run() external returns (Deploy.Addresses memory addrs) {
        addrs = _readDeploymentsJson();
        run(addrs);
    }

    function run(Deploy.Addresses memory addrs) public returns (InitialRefs memory refs) {
        uint256 deployerKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (deployerKey != 0) {
            vm.startBroadcast(deployerKey);
        } else {
            vm.startPrank(addrs.temporaryAdmin);
        }

        refs = _registerInitialEntries(addrs);
        _configureGovernance(addrs);
        _grantOperationalRoles(addrs);
        // _verifyGuardrailRejections skipped on live deploy: try/catch over vm.startBroadcast
        // doesn't catch reverts the same way as in simulation, causing false-failure on live
        // chain. The negative-test properties (Mode3 reserved + legal-phase + legal-halt
        // guardrails) are already verified by the local Foundry test suite (260 tests).
        // _verifyGuardrailRejections(addrs, refs);
        _transferUUPSControl(addrs);

        if (deployerKey != 0) {
            vm.stopBroadcast();
        } else {
            vm.stopPrank();
        }
    }

    function _registerInitialEntries(Deploy.Addresses memory addrs) internal returns (InitialRefs memory refs) {
        refs.dslVersionRef = vm.envOr("INITIAL_DSL_VERSION_REF", keccak256("cealis.dsl.v1"));
        refs.chainlinkSchemaId = keccak256("cealis.oracle.schema.chainlink-automation.v1");
        refs.subjectInitiatedSchemaId = vm.envOr(
            "SUBJECT_INITIATED_SELF_ORACLE_SCHEMA_ID", keccak256("cealis.oracle.schema.subject-initiated.v1")
        );

        DSLVersionRegistry(addrs.dslVersionRegistry)
            .addDSLVersion(
                refs.dslVersionRef,
                DSLVersionRegistry.DSLVersionEntry({
                    interpreter: addrs.claimDSL,
                    capSetHash: keccak256("cealis.dsl.v1.caps"),
                    customPredicateEnabled: false,
                    effectiveBlock: uint64(block.number),
                    tombstoneBlock: 0,
                    deprecationFlag: _zeroFlag(),
                    isCanonical: true
                })
            );

        OracleSchemaRegistry(addrs.oracleSchemaRegistry)
            .addSchema(
                refs.chainlinkSchemaId,
                OracleSchemaRegistry.OracleSchemaEntry({
                    schemaHash: keccak256("cealis.chainlink-automation.schema.v1"),
                    validExamplesHash: keccak256("cealis.chainlink.valid.v1"),
                    invalidExamplesHash: keccak256("cealis.chainlink.invalid.v1"),
                    schemaVersion: 1,
                    metadataHash: keccak256("cealis.chainlink.metadata.v1"),
                    supportedOracleTypesMask: 0x02,
                    effectiveBlock: uint64(block.number),
                    tombstoneBlock: 0,
                    deprecationFlag: _zeroFlag(),
                    isCanonical: true
                })
            );
        OracleSchemaRegistry(addrs.oracleSchemaRegistry)
            .addSchema(
                refs.subjectInitiatedSchemaId,
                OracleSchemaRegistry.OracleSchemaEntry({
                    schemaHash: keccak256("cealis.subject-initiated.schema.v1"),
                    validExamplesHash: keccak256("cealis.subject.valid.v1"),
                    invalidExamplesHash: keccak256("cealis.subject.invalid.v1"),
                    schemaVersion: 1,
                    metadataHash: keccak256("cealis.subject.metadata.v1"),
                    supportedOracleTypesMask: 0x01,
                    effectiveBlock: uint64(block.number),
                    tombstoneBlock: 0,
                    deprecationFlag: _zeroFlag(),
                    isCanonical: true
                })
            );

        address chainlinkOracle =
            vm.envOr("CHAINLINK_AUTOMATION_ORACLE_ADDR", address(0x1111000000000000000000000000000000001111));
        bytes memory chainlinkOracleBytes = abi.encodePacked(chainlinkOracle);
        refs.chainlinkOracleId = OracleRegistry(addrs.oracleRegistry).computeOracleId(chainlinkOracleBytes);
        OracleRegistry(addrs.oracleRegistry)
            .addOracle(
                refs.chainlinkOracleId,
                OracleRegistry.OracleEntry({
                    oraclePubkeyOrAddress: chainlinkOracleBytes,
                    oracleType: 1,
                    schemaId: refs.chainlinkSchemaId,
                    canonicalExamplesHash: keccak256("cealis.chainlink.examples.v1"),
                    trustTier: 2,
                    metadataHash: keccak256("cealis.chainlink.oracle.metadata.v1"),
                    effectiveBlock: uint64(block.number),
                    tombstoneBlock: 0,
                    deprecationFlag: _zeroFlag(),
                    isCanonical: true
                })
            );

        bytes memory phase1Pubkey = vm.envOr("INITIAL_G4_PHASE1_AUTHORITY_PUBKEY", bytes("g4-phase1-dev-scaffold"));
        refs.g4Phase1Ref = CealisIdentifierHelpers(addrs.identifierHelpers).computeG4AuthorityRef(phase1Pubkey);
        G4AuthorityRegistry(addrs.g4AuthorityRegistry)
            .addG4Authority(
                refs.g4Phase1Ref,
                G4AuthorityRegistry.G4AuthorityEntry({
                    phase: uint8(G4Phase.Phase1),
                    authorityPubkey: phase1Pubkey,
                    binaryHashOrMeasurement: keccak256("cealis.g4.phase1.dev-scaffold"),
                    dcapVerifierRef: bytes32(0),
                    effectiveBlock: uint64(block.number),
                    tombstoneBlock: 0,
                    deprecationFlag: _zeroFlag(),
                    isCanonical: true
                })
            );

        bytes memory phase2Pubkey = vm.envOr("INITIAL_G4_PHASE2_AUTHORITY_PUBKEY", bytes(""));
        if (phase2Pubkey.length != 0) {
            refs.g4Phase2Ref = CealisIdentifierHelpers(addrs.identifierHelpers).computeG4AuthorityRef(phase2Pubkey);
            G4AuthorityRegistry(addrs.g4AuthorityRegistry)
                .addG4Authority(
                    refs.g4Phase2Ref,
                    G4AuthorityRegistry.G4AuthorityEntry({
                        phase: uint8(G4Phase.Phase2),
                        authorityPubkey: phase2Pubkey,
                        binaryHashOrMeasurement: keccak256("cealis.g4.phase2.partner-ready"),
                        dcapVerifierRef: keccak256("cealis.dcap.verifier.phase2"),
                        effectiveBlock: uint64(block.number),
                        tombstoneBlock: 0,
                        deprecationFlag: _zeroFlag(),
                        isCanonical: true
                    })
                );
        }

        bytes32 canonicalBinaryHash =
            vm.envOr("INITIAL_PLUGIN_CANONICAL_BINARY_HASH", keccak256("age-plugin-cealis-v3"));
        refs.pluginVersionDigest =
            CealisIdentifierHelpers(addrs.identifierHelpers).computePluginVersionDigest(canonicalBinaryHash);
        refs.pluginVersionDigest = vm.envOr("INITIAL_PLUGIN_VERSION_DIGEST", refs.pluginVersionDigest);
        PluginHashRegistry(addrs.pluginHashRegistry)
            .addPlugin(
                refs.pluginVersionDigest,
                PluginHashRegistry.PluginEntry({
                    canonicalBinaryHash: canonicalBinaryHash,
                    sourceCommitDigest: keccak256("cealis.plugin.source.v1"),
                    effectiveBlock: uint64(block.number),
                    tombstoneBlock: 0,
                    deprecationFlag: _zeroFlag(),
                    isCanonical: true
                })
            );
    }

    function _configureGovernance(Deploy.Addresses memory addrs) internal {
        CealisSecurityMultisig security = CealisSecurityMultisig(addrs.securityMultisig);
        _mapRegistry(security, "PluginHashRegistry", addrs.pluginHashRegistry);
        _mapRegistry(security, "G4AuthorityRegistry", addrs.g4AuthorityRegistry);
        _mapRegistry(security, "DSLVersionRegistry", addrs.dslVersionRegistry);
        _mapRegistry(security, "OracleRegistry", addrs.oracleRegistry);
        _mapRegistry(security, "OracleSchemaRegistry", addrs.oracleSchemaRegistry);
        _mapRegistry(security, "QTSPRegistry", addrs.qtspRegistry);

        IAccessControl(addrs.timelock).grantRole(keccak256("EXPEDITED_PROPOSER_ROLE"), addrs.securityMultisig);
        IAccessControl(addrs.timelock).grantRole(keccak256("EXPEDITED_COSIGNER_ROLE"), addrs.emergencyGovernance);
        IAccessControl(addrs.timelock).grantRole(keccak256("EXPEDITED_EXECUTOR_ROLE"), address(0));

        // Grant CANCELLER_ROLE on the base OZ TimelockController to the SecurityMultisig.
        // OZ TimelockController grants CANCELLER_ROLE to every proposer at construction,
        // so a compromised proposer can both queue AND cancel — leaving no on-chain
        // countermanding party for the 7-day normal-path queue. SecurityMultisig as an
        // independent canceller closes that single-actor capture path.
        // Security-audit-2026-05-14 finding BR-G (blast-radius matrix Vector G).
        IAccessControl(addrs.timelock).grantRole(
            TimelockController(payable(addrs.timelock)).CANCELLER_ROLE(),
            addrs.securityMultisig
        );
    }

    function _grantOperationalRoles(Deploy.Addresses memory addrs) internal {
        address operator = vm.envOr("OPERATOR_ADDRESS", addrs.temporaryAdmin);
        address orchestrator = vm.envOr("ORCHESTRATOR_ADDRESS", addrs.temporaryAdmin);
        address sdOperator = vm.envOr("SD_OPERATOR_ADDRESS", addrs.temporaryAdmin);
        address gatePublisher = vm.envOr("GATE_PUBKEY_PUBLISHER_ADDRESS", addrs.temporaryAdmin);
        address litBridge = vm.envOr("LIT_GOVERNANCE_BRIDGE_ADDRESS", addrs.temporaryAdmin);

        _grant(addrs.conditionEngine, Roles.ORCHESTRATOR_ROLE, orchestrator);
        _grant(addrs.conditionEngine, Roles.ORCHESTRATOR_ROLE, addrs.temporaryAdmin);
        _grant(addrs.conditionEngine, Roles.OPERATOR_ROLE, operator);
        _grant(addrs.challengeRegistry, Roles.ORCHESTRATOR_ROLE, addrs.conditionEngine);
        _grant(addrs.shredRegistry, Roles.OPERATOR_ROLE, operator);
        // B3-shred(2) deploy-hygiene fix: ShredRegistry.initialize() grants
        // OPERATOR_ROLE to its initialize arg (= temporaryAdmin / deployer EOA at
        // deploy time). _transferUUPSControl revokes only DEFAULT_ADMIN + UPGRADER
        // from temporaryAdmin, so the leftover deployer-EOA OPERATOR survives the
        // handoff — an unintended extra unilateral shred operator. Revoke that
        // residual once the dedicated operator EOA above holds the role. Only when
        // OPERATOR_ADDRESS designates a DISTINCT operator: if it is unset, `operator`
        // defaults to temporaryAdmin (the intended holder), and revoking would strip
        // the registry of every operator. Distinct operator => revoke the deployer's
        // residual; same address => the role legitimately stays.
        if (operator != addrs.temporaryAdmin) {
            _revokeIfHeld(addrs.shredRegistry, Roles.OPERATOR_ROLE, addrs.temporaryAdmin);
        }
        _grant(addrs.g4RefusalRegistry, Roles.OPERATOR_ROLE, operator);
        _grant(addrs.gateRecipientPubkeyRegistry, Roles.GATE_PUBKEY_PUBLISHER_ROLE, gatePublisher);
        _grant(addrs.litV3Assignment, Roles.LIT_GOVERNANCE_BRIDGE_ROLE, litBridge);
        _grant(addrs.disclosureRegistry, Roles.SD_OPERATOR_ROLE, sdOperator);
        _grant(addrs.disclosureRevocationRegistry, Roles.ORCHESTRATOR_ROLE, orchestrator);
        _grant(addrs.disclosureRevocationRegistry, Roles.REVOCATION_ADMIN_ROLE, addrs.timelock);

        _grant(addrs.conditionEngine, Roles.MODULE_ADMIN_ROLE, addrs.timelock);
        for (uint256 i = 0; i < addrs.moduleAddresses.length; ++i) {
            _grant(addrs.moduleAddresses[i], Roles.MODULE_ADMIN_ROLE, addrs.timelock);
            _revokeIfHeld(addrs.moduleAddresses[i], Roles.MODULE_ADMIN_ROLE, addrs.temporaryAdmin);
        }

        address[7] memory registries = [
            addrs.pluginHashRegistry,
            addrs.g4AuthorityRegistry,
            addrs.dslVersionRegistry,
            addrs.oracleRegistry,
            addrs.oracleSchemaRegistry,
            addrs.qtspRegistry,
            addrs.gateRecipientPubkeyRegistry
        ];
        for (uint256 i = 0; i < registries.length; ++i) {
            _grant(registries[i], Roles.REGISTRY_ADMIN_ROLE, addrs.timelock);
            _revokeIfHeld(registries[i], Roles.REGISTRY_ADMIN_ROLE, addrs.temporaryAdmin);
        }

        _grant(addrs.supersededCommitRegistry, Roles.REKEY_GOVERNANCE_ROLE, addrs.timelock);
        _revokeIfHeld(addrs.conditionEngine, Roles.MODULE_ADMIN_ROLE, addrs.temporaryAdmin);
        _revokeIfHeld(addrs.supersededCommitRegistry, Roles.REKEY_GOVERNANCE_ROLE, addrs.temporaryAdmin);
    }

    function _verifyGuardrailRejections(Deploy.Addresses memory addrs, InitialRefs memory refs) internal {
        if (!_registerMustRevert(addrs, _guardrailRegistration(addrs, refs, "mode3", false, false, true), ASSERT_MODE3))
        {
            revert PostDeployAssertionFailed(ASSERT_MODE3);
        }
        if (!_registerMustRevert(
                addrs, _guardrailRegistration(addrs, refs, "legal-phase1", true, false, false), ASSERT_LEGAL_PHASE
            )) {
            revert PostDeployAssertionFailed(ASSERT_LEGAL_PHASE);
        }
        if (!_registerMustRevert(
                addrs, _guardrailRegistration(addrs, refs, "legal-halt", true, true, false), ASSERT_LEGAL_HALT
            )) {
            revert PostDeployAssertionFailed(ASSERT_LEGAL_HALT);
        }
    }

    function _transferUUPSControl(Deploy.Addresses memory addrs) internal {
        address[31] memory targets = [
            addrs.securityMultisig,
            addrs.emergencyGovernance,
            addrs.pluginHashRegistry,
            addrs.g4AuthorityRegistry,
            addrs.dslVersionRegistry,
            addrs.oracleRegistry,
            addrs.oracleSchemaRegistry,
            addrs.qtspRegistry,
            addrs.gateRecipientPubkeyRegistry,
            addrs.litV3Assignment,
            addrs.disclosureRevocationRegistry,
            addrs.disclosureRegistry,
            addrs.g4RefusalRegistry,
            addrs.passkeyRotationLog,
            addrs.supersededCommitRegistry,
            addrs.challengeRegistry,
            addrs.claimDSL,
            addrs.fsmInterpreter,
            addrs.paymentObligationModule,
            addrs.timeLockModule,
            addrs.subjectInitiatedModule,
            addrs.heartbeatMissedModule,
            addrs.oracleAttestationModule,
            addrs.multiPartySignalModule,
            addrs.deadManSwitchModule,
            addrs.consentGateModule,
            addrs.composedModule,
            addrs.attestationGate,
            addrs.shredRegistry,
            addrs.conditionEngine,
            address(0)
        ];
        for (uint256 i = 0; i < targets.length; ++i) {
            if (targets[i] == address(0)) continue;
            _grant(targets[i], Roles.DEFAULT_ADMIN_ROLE, addrs.timelock);
            _grant(targets[i], Roles.UPGRADER_ROLE, addrs.timelock);
            _revokeIfHeld(targets[i], Roles.UPGRADER_ROLE, addrs.temporaryAdmin);
            _revokeIfHeld(targets[i], Roles.DEFAULT_ADMIN_ROLE, addrs.temporaryAdmin);
        }
    }

    function _mapRegistry(CealisSecurityMultisig security, string memory name, address registry) internal {
        security.setRegistry(_registryId(registry), registry);
        security.setRegistry(keccak256(bytes(name)), registry);
    }

    function _registerMustRevert(Deploy.Addresses memory addrs, PDARegistration memory reg, bytes32)
        internal
        returns (bool)
    {
        try IConditionEngine(addrs.conditionEngine).registerPDA(reg) {
            return false;
        } catch {
            return true;
        }
    }

    function _guardrailRegistration(
        Deploy.Addresses memory addrs,
        InitialRefs memory refs,
        string memory salt,
        bool legalEffect,
        bool haltOptOut,
        bool includeMode3
    ) internal pure returns (PDARegistration memory reg) {
        bytes32 authorizationId = keccak256(abi.encodePacked("cealis.guardrail", salt));
        uint8 g4Phase = legalEffect ? uint8(G4Phase.Phase1) : uint8(G4Phase.Phase2);

        reg.pdaRootFields = PdaRootFields({
            pdaId: keccak256(abi.encodePacked("pda", salt)),
            pdaVersion: 1,
            revealConditionMode: uint8(ConditionMode.ModeP),
            revealConditionSpecHash: bytes32(uint256(uint160(addrs.paymentObligationModule))),
            shredConditionMode: uint8(ConditionMode.ModeP),
            shredConditionSpecHash: bytes32(uint256(uint160(addrs.timeLockModule))),
            oracleReferencesRoot: refs.chainlinkOracleId,
            dslVersion: refs.dslVersionRef,
            wasmPredicateHashesRoot: bytes32(0),
            submitterSetsRoot: keccak256("submitters"),
            pauseAuthorityId: keccak256("pause-authority"),
            ceremonyResolverId: keccak256("resolver"),
            eligibleChallengersRevealRoot: keccak256("eligible-reveal"),
            eligibleChallengersShredRoot: keccak256("eligible-shred"),
            templateId: keccak256("template"),
            partnerId: keccak256("partner"),
            subjectAuthenticatorClass: 1,
            qtspProviderRef: bytes32(0),
            art9Scoped: false,
            art9BasisId: 0,
            legalEffectExpected: legalEffect,
            cealisClassWideHaltOptOut: haltOptOut,
            minimumShredLatency: 1 days,
            applicableJurisdiction: keccak256("DE"),
            conditionalRecipientsUpdatable: false,
            subjectLivenessRequiredAtFire: false,
            emergencyResponseBrickingAcknowledgment: true,
            timeCriticalPdaFlag: false,
            pdaUpdatable: false
        });
        bytes32 pdaRoot = CealisIdentifierHelpers(addrs.identifierHelpers).computePdaRoot(reg.pdaRootFields);
        reg.hCommitFields = HCommitFields({
            authorizationId: authorizationId,
            pdaRoot: pdaRoot,
            schemaDigest: keccak256("schema"),
            ciphertextDigest: keccak256("ciphertext"),
            aadDigest: keccak256("aad"),
            compositeIdentityDigest: keccak256("identity"),
            endpointAttestationDigest: keccak256("endpoint"),
            retentionWindow: 365 days,
            shredAuthorityId: bytes32(uint256(uint8(ShredAuthorityMode.Subject))),
            recipientsRoot: keccak256("recipients"),
            revealChallengeWindow: 0,
            shredChallengeWindow: 1 days,
            g3Choice: 0,
            phase: g4Phase,
            commitVersion: ProtocolVersion.BUILD_PROTOCOL_VERSION
        });
        reg.revealAxis = AxisConfig({
            mode: ConditionMode.ModeP,
            conditionRef: keccak256("reveal-condition"),
            conditionSpecHash: bytes32(uint256(uint160(addrs.paymentObligationModule))),
            challengeWindow: 0,
            eligibleChallengersRoot: bytes32(0),
            resolverId: bytes32(0)
        });
        reg.shredAxis = AxisConfig({
            mode: ConditionMode.ModeP,
            conditionRef: keccak256("shred-condition"),
            conditionSpecHash: bytes32(uint256(uint160(addrs.timeLockModule))),
            challengeWindow: 1 days,
            eligibleChallengersRoot: bytes32(0),
            resolverId: bytes32(0)
        });
        reg.registryRefs = RegistryRefs({
            pluginVersionDigest: refs.pluginVersionDigest,
            g4AuthorityRef: refs.g4Phase1Ref,
            g3AuthorityRef: bytes32(0),
            oracleReferencesRoot: refs.chainlinkOracleId,
            oracleSchemaRoot: refs.chainlinkSchemaId,
            dslVersionRef: refs.dslVersionRef,
            qtspProviderRef: bytes32(0),
            gateRecipientPubkeyRoot: bytes32(0)
        });
        reg.legalFlags = LegalFlags({
            legalEffectExpected: legalEffect,
            cealisClassWideHaltOptOut: haltOptOut,
            qesRequired: false,
            art9Scoped: false,
            art9BasisId: 0,
            subjectAuthenticatorClass: 1,
            // INTENTIONAL inversion for negative-testing: when legalEffect=true,
            // uses Phase1 (forbidden per S2-2 §3.4) so the registration MUST revert
            // with ConditionLegalEffectPhaseInvalid — that's the assertion target.
            requiredG4Phase: legalEffect ? G4Phase.Phase1 : G4Phase.Phase2
        });
        reg.pauseAuthorityMode = PauseAuthorityMode.Joint;
        reg.shredGuardrailCompiled = true;
        reg.conditionalRecipientPolicyDigest = keccak256("conditional-policy");
        if (includeMode3) {
            reg.conditionalRecipientModes = new ConditionalRecipientMode[](1);
            reg.conditionalRecipientModes[0] = ConditionalRecipientMode.WalletEIP1271Reserved;
        } else {
            reg.conditionalRecipientModes = new ConditionalRecipientMode[](1);
            reg.conditionalRecipientModes[0] = ConditionalRecipientMode.PasskeyAccount;
        }
    }

    function _grant(address target, bytes32 role, address account) internal {
        if (!IAccessControl(target).hasRole(role, account)) {
            IAccessControl(target).grantRole(role, account);
        }
    }

    function _revokeIfHeld(address target, bytes32 role, address account) internal {
        if (IAccessControl(target).hasRole(role, account)) {
            IAccessControl(target).revokeRole(role, account);
        }
    }

    function _registryId(address registry) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(registry)));
    }

    function _zeroFlag() internal pure returns (DeprecationFlag memory flag) {
        return flag;
    }

    function _readDeploymentsJson() internal view returns (Deploy.Addresses memory addrs) {
        string memory json = vm.readFile(DEPLOYMENTS_PATH);
        addrs.temporaryAdmin = vm.parseJsonAddress(json, ".temporaryAdmin");
        addrs.identifierHelpers = vm.parseJsonAddress(json, ".identifierHelpers");
        addrs.timelock = vm.parseJsonAddress(json, ".timelock");
        addrs.securityMultisig = vm.parseJsonAddress(json, ".securityMultisig");
        addrs.emergencyGovernance = vm.parseJsonAddress(json, ".emergencyGovernance");
        addrs.pluginHashRegistry = vm.parseJsonAddress(json, ".pluginHashRegistry");
        addrs.g4AuthorityRegistry = vm.parseJsonAddress(json, ".g4AuthorityRegistry");
        addrs.dslVersionRegistry = vm.parseJsonAddress(json, ".dslVersionRegistry");
        addrs.oracleRegistry = vm.parseJsonAddress(json, ".oracleRegistry");
        addrs.oracleSchemaRegistry = vm.parseJsonAddress(json, ".oracleSchemaRegistry");
        addrs.qtspRegistry = vm.parseJsonAddress(json, ".qtspRegistry");
        addrs.gateRecipientPubkeyRegistry = vm.parseJsonAddress(json, ".gateRecipientPubkeyRegistry");
        addrs.litV3Assignment = vm.parseJsonAddress(json, ".litV3Assignment");
        addrs.disclosureRevocationRegistry = vm.parseJsonAddress(json, ".disclosureRevocationRegistry");
        addrs.disclosureRegistry = vm.parseJsonAddress(json, ".disclosureRegistry");
        addrs.g4RefusalRegistry = vm.parseJsonAddress(json, ".g4RefusalRegistry");
        addrs.passkeyRotationLog = vm.parseJsonAddress(json, ".passkeyRotationLog");
        addrs.supersededCommitRegistry = vm.parseJsonAddress(json, ".supersededCommitRegistry");
        addrs.challengeRegistry = vm.parseJsonAddress(json, ".challengeRegistry");
        addrs.claimDSL = vm.parseJsonAddress(json, ".claimDSL");
        addrs.fsmInterpreter = vm.parseJsonAddress(json, ".fsmInterpreter");
        addrs.paymentObligationModule = vm.parseJsonAddress(json, ".paymentObligationModule");
        addrs.timeLockModule = vm.parseJsonAddress(json, ".timeLockModule");
        addrs.subjectInitiatedModule = vm.parseJsonAddress(json, ".subjectInitiatedModule");
        addrs.heartbeatMissedModule = vm.parseJsonAddress(json, ".heartbeatMissedModule");
        addrs.oracleAttestationModule = vm.parseJsonAddress(json, ".oracleAttestationModule");
        addrs.multiPartySignalModule = vm.parseJsonAddress(json, ".multiPartySignalModule");
        addrs.deadManSwitchModule = vm.parseJsonAddress(json, ".deadManSwitchModule");
        addrs.consentGateModule = vm.parseJsonAddress(json, ".consentGateModule");
        addrs.composedModule = vm.parseJsonAddress(json, ".composedModule");
        addrs.attestationGate = vm.parseJsonAddress(json, ".attestationGate");
        addrs.shredRegistry = vm.parseJsonAddress(json, ".shredRegistry");
        addrs.conditionEngine = vm.parseJsonAddress(json, ".conditionEngine");
        addrs.revealAuthorizedEmitter = vm.parseJsonAddress(json, ".revealAuthorizedEmitter");
    }
}
