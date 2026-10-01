// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Script } from "forge-std/Script.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { AttestationGate } from "../src/attestation/AttestationGate.sol";
import { ChallengeRegistry } from "../src/challenge/ChallengeRegistry.sol";
import { ClaimDSL } from "../src/dsl/ClaimDSL.sol";
import { ConditionEngine } from "../src/engine/ConditionEngine.sol";
import { FSMInterpreter } from "../src/fsm/FSMInterpreter.sol";
import { G4RefusalRegistry } from "../src/g4-refusal/G4RefusalRegistry.sol";
import { GateRecipientPubkeyRegistry } from "../src/gate-recipient/GateRecipientPubkeyRegistry.sol";
import { CealisIdentifierHelpers } from "../src/helpers/CealisIdentifierHelpers.sol";
import { LitV3Assignment } from "../src/lit/LitV3Assignment.sol";
import { ComposedModule } from "../src/modules/ComposedModule.sol";
import { ConsentGateModule } from "../src/modules/ConsentGateModule.sol";
import { DeadManSwitchModule } from "../src/modules/DeadManSwitchModule.sol";
import { HeartbeatMissedModule } from "../src/modules/HeartbeatMissedModule.sol";
import { MultiPartySignalModule } from "../src/modules/MultiPartySignalModule.sol";
import { OracleAttestationModule } from "../src/modules/OracleAttestationModule.sol";
import { PaymentObligationModule } from "../src/modules/PaymentObligationModule.sol";
import { SubjectInitiatedModule } from "../src/modules/SubjectInitiatedModule.sol";
import { TimeLockModule } from "../src/modules/TimeLockModule.sol";
import { PasskeyRotationLog } from "../src/passkey/PasskeyRotationLog.sol";
import { DisclosureRegistry } from "../src/disclosure/DisclosureRegistry.sol";
import { DisclosureRevocationRegistry } from "../src/disclosure/DisclosureRevocationRegistry.sol";
import { EmergencyGovernance } from "../src/governance/EmergencyGovernance.sol";
import { CealisSecurityMultisig } from "../src/governance/CealisSecurityMultisig.sol";
import { CealisTimelockController } from "../src/governance/CealisTimelockController.sol";
import { G4AuthorityRegistry } from "../src/registries/G4AuthorityRegistry.sol";
import { DSLVersionRegistry } from "../src/registries/DSLVersionRegistry.sol";
import { OracleRegistry } from "../src/registries/OracleRegistry.sol";
import { OracleSchemaRegistry } from "../src/registries/OracleSchemaRegistry.sol";
import { PluginHashRegistry } from "../src/registries/PluginHashRegistry.sol";
import { QTSPRegistry } from "../src/registries/QTSPRegistry.sol";
import { ShredRegistry } from "../src/shred/ShredRegistry.sol";
import { SupersededCommitRegistry } from "../src/superseded/SupersededCommitRegistry.sol";

contract Deploy is Script {
    string internal constant DEPLOYMENTS_PATH = "deployments/base-sepolia.json";
    uint256 internal constant CREATES_BEFORE_ATTESTATION_GATE_PROXY = 57;
    uint256 internal constant CREATES_BEFORE_CONDITION_ENGINE_PROXY = 61;

    struct Addresses {
        address temporaryAdmin;
        address identifierHelpers;
        address timelock;
        address securityMultisig;
        address emergencyGovernance;
        address pluginHashRegistry;
        address g4AuthorityRegistry;
        address dslVersionRegistry;
        address oracleRegistry;
        address oracleSchemaRegistry;
        address qtspRegistry;
        address gateRecipientPubkeyRegistry;
        address litV3Assignment;
        address disclosureRevocationRegistry;
        address disclosureRegistry;
        address g4RefusalRegistry;
        address passkeyRotationLog;
        address supersededCommitRegistry;
        address challengeRegistry;
        address claimDSL;
        address fsmInterpreter;
        address paymentObligationModule;
        address timeLockModule;
        address subjectInitiatedModule;
        address heartbeatMissedModule;
        address oracleAttestationModule;
        address multiPartySignalModule;
        address deadManSwitchModule;
        address consentGateModule;
        address composedModule;
        address attestationGate;
        address shredRegistry;
        address conditionEngine;
        address revealAuthorizedEmitter;
        address[] moduleAddresses;
    }

    function run() external returns (Addresses memory addrs) {
        uint256 deployerKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        address createDeployer;
        if (deployerKey != 0) {
            createDeployer = vm.addr(deployerKey);
            addrs.temporaryAdmin = createDeployer;
            vm.startBroadcast(deployerKey);
        } else {
            createDeployer = address(this);
            addrs.temporaryAdmin = createDeployer;
        }

        uint256 startNonce = vm.getNonce(createDeployer);
        // Mode-dependent nonce adjustment for create-address prediction:
        // - Test mode (deployerKey == 0): createDeployer == address(this) (the Deploy
        //   script contract). EIP-161 sets a fresh contract's nonce to 1 on creation,
        //   and vm.getNonce returns 1 BEFORE any `new` calls. AttestationGate proxy is
        //   the 58th create (nonce 58 = 1 + 57), CE proxy is the 62nd (nonce 62 = 1 + 61).
        //   AG_OFFSET=57, CE_OFFSET=61 work directly.
        // - Broadcast mode (deployerKey != 0): createDeployer is a fresh EOA whose
        //   nonce starts at 0, but Foundry's forge script pre-deploys the script
        //   contract via a broadcaster-signed tx, consuming nonce 0. So our run()'s
        //   first internal `new` happens at the broadcaster's nonce 1 (NOT 0). Adjust
        //   by +1 to keep the offsets identical to test mode.
        uint256 broadcastModeOffset = deployerKey != 0 ? 1 : 0;
        address predictedAttestationGate = vm.computeCreateAddress(
            createDeployer, startNonce + broadcastModeOffset + CREATES_BEFORE_ATTESTATION_GATE_PROXY
        );
        address predictedConditionEngine = vm.computeCreateAddress(
            createDeployer, startNonce + broadcastModeOffset + CREATES_BEFORE_CONDITION_ENGINE_PROXY
        );

        address[] memory timelockProposers = _envAddressArray("TIMELOCK_PROPOSERS", addrs.temporaryAdmin);
        address[] memory timelockExecutors = _envAddressArray("TIMELOCK_EXECUTORS", addrs.temporaryAdmin);
        address[] memory securityCouncilSigners = _envAddressArray("SECURITY_COUNCIL_SIGNERS", addrs.temporaryAdmin);
        address[] memory emergencySigners = _envAddressArray("EMERGENCY_GOVERNANCE_SIGNERS", addrs.temporaryAdmin);

        // 1. TimelockController.
        addrs.timelock =
            address(new CealisTimelockController(7 days, timelockProposers, timelockExecutors, addrs.temporaryAdmin));

        // 2. CealisSecurityMultisig + EmergencyGovernance.
        addrs.securityMultisig = _deploySecurity(addrs.temporaryAdmin, addrs.timelock, securityCouncilSigners);
        addrs.emergencyGovernance =
            _deployEmergency(addrs.temporaryAdmin, addrs.securityMultisig, addrs.timelock, emergencySigners);
        CealisSecurityMultisig(addrs.securityMultisig).setEmergencyGovernance(addrs.emergencyGovernance);

        addrs.identifierHelpers = address(new CealisIdentifierHelpers());

        // 3. Registry implementations and proxies.
        addrs.pluginHashRegistry = _deployUUPS(
            address(new PluginHashRegistry()),
            abi.encodeCall(
                PluginHashRegistry.initialize,
                (
                    addrs.temporaryAdmin,
                    addrs.securityMultisig,
                    addrs.emergencyGovernance,
                    addrs.temporaryAdmin,
                    addrs.identifierHelpers
                )
            )
        );
        addrs.g4AuthorityRegistry = _deployUUPS(
            address(new G4AuthorityRegistry()),
            abi.encodeCall(
                G4AuthorityRegistry.initialize,
                (
                    addrs.temporaryAdmin,
                    addrs.securityMultisig,
                    addrs.emergencyGovernance,
                    addrs.temporaryAdmin,
                    addrs.temporaryAdmin,
                    addrs.identifierHelpers
                )
            )
        );
        addrs.dslVersionRegistry = _deployUUPS(
            address(new DSLVersionRegistry()),
            abi.encodeCall(
                DSLVersionRegistry.initialize,
                (addrs.temporaryAdmin, addrs.securityMultisig, addrs.emergencyGovernance, addrs.temporaryAdmin)
            )
        );
        addrs.oracleRegistry = _deployUUPS(
            address(new OracleRegistry()),
            abi.encodeCall(
                OracleRegistry.initialize,
                (addrs.temporaryAdmin, addrs.securityMultisig, addrs.emergencyGovernance, addrs.temporaryAdmin)
            )
        );
        addrs.oracleSchemaRegistry = _deployUUPS(
            address(new OracleSchemaRegistry()),
            abi.encodeCall(
                OracleSchemaRegistry.initialize,
                (addrs.temporaryAdmin, addrs.securityMultisig, addrs.emergencyGovernance, addrs.temporaryAdmin)
            )
        );
        addrs.qtspRegistry = _deployUUPS(
            address(new QTSPRegistry()),
            abi.encodeCall(
                QTSPRegistry.initialize,
                (addrs.temporaryAdmin, addrs.securityMultisig, addrs.emergencyGovernance, addrs.temporaryAdmin)
            )
        );

        // 4. GateRecipientPubkeyRegistry.
        addrs.gateRecipientPubkeyRegistry = _deployUUPS(
            address(new GateRecipientPubkeyRegistry()),
            abi.encodeCall(GateRecipientPubkeyRegistry.initialize, (addrs.temporaryAdmin))
        );

        // 5. LitV3Assignment.
        addrs.litV3Assignment = _deployUUPS(
            address(new LitV3Assignment()), abi.encodeCall(LitV3Assignment.initialize, (addrs.temporaryAdmin))
        );

        // 6. DisclosureRevocationRegistry first, then DisclosureRegistry which depends on it.
        addrs.disclosureRevocationRegistry = _deployUUPS(
            address(new DisclosureRevocationRegistry()),
            abi.encodeCall(DisclosureRevocationRegistry.initialize, (addrs.temporaryAdmin))
        );
        addrs.disclosureRegistry = _deployUUPS(
            address(new DisclosureRegistry()),
            abi.encodeCall(DisclosureRegistry.initialize, (addrs.temporaryAdmin, addrs.disclosureRevocationRegistry))
        );

        // 7. G4RefusalRegistry.
        addrs.g4RefusalRegistry = _deployUUPS(
            address(new G4RefusalRegistry()), abi.encodeCall(G4RefusalRegistry.initialize, (addrs.temporaryAdmin))
        );

        // 8. PasskeyRotationLog.
        addrs.passkeyRotationLog = _deployUUPS(
            address(new PasskeyRotationLog()), abi.encodeCall(PasskeyRotationLog.initialize, (addrs.temporaryAdmin))
        );

        // 9. SupersededCommitRegistry.
        addrs.supersededCommitRegistry = _deployUUPS(
            address(new SupersededCommitRegistry()),
            abi.encodeCall(SupersededCommitRegistry.initialize, (addrs.temporaryAdmin, addrs.identifierHelpers))
        );

        // 10. ChallengeRegistry.
        addrs.challengeRegistry = _deployUUPS(
            address(new ChallengeRegistry()), abi.encodeCall(ChallengeRegistry.initialize, (addrs.temporaryAdmin))
        );

        // 11. ClaimDSL interpreter.
        addrs.claimDSL = _deployUUPS(
            address(new ClaimDSL()),
            abi.encodeCall(ClaimDSL.initialize, (addrs.temporaryAdmin, addrs.dslVersionRegistry))
        );

        // 12. FSMInterpreter.
        addrs.fsmInterpreter = _deployUUPS(
            address(new FSMInterpreter()),
            abi.encodeCall(FSMInterpreter.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );

        // 13. Condition modules.
        addrs.paymentObligationModule = _deployUUPS(
            address(new PaymentObligationModule()),
            abi.encodeCall(PaymentObligationModule.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );
        addrs.timeLockModule = _deployUUPS(
            address(new TimeLockModule()),
            abi.encodeCall(TimeLockModule.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );
        addrs.subjectInitiatedModule = _deployUUPS(
            address(new SubjectInitiatedModule()),
            abi.encodeCall(SubjectInitiatedModule.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );
        addrs.heartbeatMissedModule = _deployUUPS(
            address(new HeartbeatMissedModule()),
            abi.encodeCall(HeartbeatMissedModule.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );
        addrs.oracleAttestationModule = _deployUUPS(
            address(new OracleAttestationModule()),
            abi.encodeCall(
                OracleAttestationModule.initialize,
                (addrs.temporaryAdmin, predictedConditionEngine, predictedAttestationGate)
            )
        );
        addrs.multiPartySignalModule = _deployUUPS(
            address(new MultiPartySignalModule()),
            abi.encodeCall(MultiPartySignalModule.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );
        addrs.deadManSwitchModule = _deployUUPS(
            address(new DeadManSwitchModule()),
            abi.encodeCall(DeadManSwitchModule.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );
        addrs.consentGateModule = _deployUUPS(
            address(new ConsentGateModule()),
            abi.encodeCall(ConsentGateModule.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );
        addrs.composedModule = _deployUUPS(
            address(new ComposedModule()),
            abi.encodeCall(ComposedModule.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );
        addrs.moduleAddresses = _moduleAddresses(addrs);

        // 14. AttestationGate.
        addrs.attestationGate = _deployUUPS(
            address(new AttestationGate()),
            abi.encodeCall(
                AttestationGate.initialize,
                (
                    addrs.temporaryAdmin,
                    addrs.oracleRegistry,
                    addrs.oracleSchemaRegistry,
                    addrs.dslVersionRegistry,
                    addrs.claimDSL
                )
            )
        );

        // 15. ShredRegistry.
        addrs.shredRegistry = _deployUUPS(
            address(new ShredRegistry()),
            abi.encodeCall(ShredRegistry.initialize, (addrs.temporaryAdmin, predictedConditionEngine))
        );

        // 16. ConditionEngine.
        ConditionEngine.EngineConfig memory config;
        config.timelock = addrs.temporaryAdmin;
        config.helpers = addrs.identifierHelpers;
        config.fsmInterpreter = addrs.fsmInterpreter;
        config.claimDSL = addrs.claimDSL;
        config.attestationGate = addrs.attestationGate;
        config.challengeRegistry = addrs.challengeRegistry;
        config.shredRegistry = addrs.shredRegistry;
        config.g4RefusalRegistry = addrs.g4RefusalRegistry;
        config.gateRecipientPubkeyRegistry = addrs.gateRecipientPubkeyRegistry;
        config.litV3Assignment = addrs.litV3Assignment;
        config.supersededCommitRegistry = addrs.supersededCommitRegistry;
        config.pluginHashRegistry = addrs.pluginHashRegistry;
        config.g4AuthorityRegistry = addrs.g4AuthorityRegistry;
        config.dslVersionRegistry = addrs.dslVersionRegistry;
        config.oracleRegistry = addrs.oracleRegistry;
        config.qtspRegistry = addrs.qtspRegistry;
        config.oracleSchemaRegistry = addrs.oracleSchemaRegistry;
        config.conditionModules = _moduleAddressArray(addrs);
        addrs.conditionEngine =
            _deployUUPS(address(new ConditionEngine()), abi.encodeCall(ConditionEngine.initialize, (config)));
        require(addrs.conditionEngine == predictedConditionEngine, "condition engine prediction drift");

        // 17. Optional RevealAuthorizedEmitter. Phase D2 did not extract it in this tree.
        addrs.revealAuthorizedEmitter = address(0);

        if (deployerKey != 0) vm.stopBroadcast();
        _maybeWriteDeploymentsJson(addrs);
        return addrs;
    }

    function _deploySecurity(address admin, address timelock, address[] memory signers) internal returns (address) {
        address implementation = address(new CealisSecurityMultisig());
        bytes memory init = abi.encodeCall(CealisSecurityMultisig.initialize, (admin, timelock, address(1), signers));
        return _deployUUPS(implementation, init);
    }

    function _deployEmergency(address admin, address securityMultisig, address timelock, address[] memory signers)
        internal
        returns (address)
    {
        address implementation = address(new EmergencyGovernance());
        bytes memory init = abi.encodeCall(EmergencyGovernance.initialize, (admin, securityMultisig, timelock, signers));
        return _deployUUPS(implementation, init);
    }

    function _deployUUPS(address implementation, bytes memory initData) internal returns (address) {
        return address(new ERC1967Proxy(implementation, initData));
    }

    function _moduleAddresses(Addresses memory addrs) internal pure returns (address[] memory modules) {
        modules = new address[](9);
        modules[0] = addrs.paymentObligationModule;
        modules[1] = addrs.timeLockModule;
        modules[2] = addrs.subjectInitiatedModule;
        modules[3] = addrs.heartbeatMissedModule;
        modules[4] = addrs.oracleAttestationModule;
        modules[5] = addrs.multiPartySignalModule;
        modules[6] = addrs.deadManSwitchModule;
        modules[7] = addrs.consentGateModule;
        modules[8] = addrs.composedModule;
    }

    function _moduleAddressArray(Addresses memory addrs) internal pure returns (address[9] memory modules) {
        modules[0] = addrs.paymentObligationModule;
        modules[1] = addrs.timeLockModule;
        modules[2] = addrs.subjectInitiatedModule;
        modules[3] = addrs.heartbeatMissedModule;
        modules[4] = addrs.oracleAttestationModule;
        modules[5] = addrs.multiPartySignalModule;
        modules[6] = addrs.deadManSwitchModule;
        modules[7] = addrs.consentGateModule;
        modules[8] = addrs.composedModule;
    }

    function _envAddressArray(string memory name, address defaultAddress)
        internal
        view
        returns (address[] memory values)
    {
        address[] memory defaults = new address[](1);
        defaults[0] = defaultAddress;
        values = vm.envOr(name, ",", defaults);
        if (values.length == 0) {
            values = defaults;
        }
    }

    function _maybeWriteDeploymentsJson(Addresses memory addrs) internal {
        if (block.chainid == 31337) return;
        string memory root = "deploy";
        vm.serializeAddress(root, "temporaryAdmin", addrs.temporaryAdmin);
        vm.serializeAddress(root, "identifierHelpers", addrs.identifierHelpers);
        vm.serializeAddress(root, "timelock", addrs.timelock);
        vm.serializeAddress(root, "securityMultisig", addrs.securityMultisig);
        vm.serializeAddress(root, "emergencyGovernance", addrs.emergencyGovernance);
        vm.serializeAddress(root, "pluginHashRegistry", addrs.pluginHashRegistry);
        vm.serializeAddress(root, "g4AuthorityRegistry", addrs.g4AuthorityRegistry);
        vm.serializeAddress(root, "dslVersionRegistry", addrs.dslVersionRegistry);
        vm.serializeAddress(root, "oracleRegistry", addrs.oracleRegistry);
        vm.serializeAddress(root, "oracleSchemaRegistry", addrs.oracleSchemaRegistry);
        vm.serializeAddress(root, "qtspRegistry", addrs.qtspRegistry);
        vm.serializeAddress(root, "gateRecipientPubkeyRegistry", addrs.gateRecipientPubkeyRegistry);
        vm.serializeAddress(root, "litV3Assignment", addrs.litV3Assignment);
        vm.serializeAddress(root, "disclosureRevocationRegistry", addrs.disclosureRevocationRegistry);
        vm.serializeAddress(root, "disclosureRegistry", addrs.disclosureRegistry);
        vm.serializeAddress(root, "g4RefusalRegistry", addrs.g4RefusalRegistry);
        vm.serializeAddress(root, "passkeyRotationLog", addrs.passkeyRotationLog);
        vm.serializeAddress(root, "supersededCommitRegistry", addrs.supersededCommitRegistry);
        vm.serializeAddress(root, "challengeRegistry", addrs.challengeRegistry);
        vm.serializeAddress(root, "claimDSL", addrs.claimDSL);
        vm.serializeAddress(root, "fsmInterpreter", addrs.fsmInterpreter);
        vm.serializeAddress(root, "paymentObligationModule", addrs.paymentObligationModule);
        vm.serializeAddress(root, "timeLockModule", addrs.timeLockModule);
        vm.serializeAddress(root, "subjectInitiatedModule", addrs.subjectInitiatedModule);
        vm.serializeAddress(root, "heartbeatMissedModule", addrs.heartbeatMissedModule);
        vm.serializeAddress(root, "oracleAttestationModule", addrs.oracleAttestationModule);
        vm.serializeAddress(root, "multiPartySignalModule", addrs.multiPartySignalModule);
        vm.serializeAddress(root, "deadManSwitchModule", addrs.deadManSwitchModule);
        vm.serializeAddress(root, "consentGateModule", addrs.consentGateModule);
        vm.serializeAddress(root, "composedModule", addrs.composedModule);
        vm.serializeAddress(root, "attestationGate", addrs.attestationGate);
        vm.serializeAddress(root, "shredRegistry", addrs.shredRegistry);
        vm.serializeAddress(root, "conditionEngine", addrs.conditionEngine);
        string memory json = vm.serializeAddress(root, "revealAuthorizedEmitter", addrs.revealAuthorizedEmitter);
        vm.writeJson(json, DEPLOYMENTS_PATH);
    }
}
