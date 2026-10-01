// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { ConditionEngine } from "../src/engine/ConditionEngine.sol";
import { FSMInterpreter } from "../src/fsm/FSMInterpreter.sol";
import { CealisIdentifierHelpers } from "../src/helpers/CealisIdentifierHelpers.sol";
import { ShredRegistry } from "../src/shred/ShredRegistry.sol";
import { IConditionModule } from "../src/engine/IConditionEngine.sol";
import {
    ConditionMode,
    ConditionalRecipientMode,
    G4Phase,
    PauseAuthorityMode,
    ProtocolVersion,
    ShredAuthorityMode
} from "../src/lib/Enums.sol";
import { Roles } from "../src/lib/Roles.sol";
import { AxisConfig, HCommitFields, PDARegistration, PdaRootFields } from "../src/lib/Structs.sol";

/// @dev A module whose `evaluate` always returns true — the Mode P predicate the
///      E2E reveal/shred axes point at so `authorizeReveal` / `authorizeShred`
///      fire deterministically against an anvil block trigger. Mirrors the
///      `AlwaysTrueModule` in test/engine/ConditionEngine.t.sol.
contract AlwaysTrueModule is IConditionModule {
    function configure(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config) external {
        emit ModuleConfigured(authorizationId, moduleRef, keccak256(config));
    }

    function advance(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata) external returns (bool terminal) {
        emit ModuleAdvanced(authorizationId, evidenceRef, true);
        return true;
    }

    function evaluate(bytes32, bytes32) external pure returns (bool) {
        return true;
    }
}

/// @title E2EAnvil — Phase 4 event-driven E2E on-chain harness.
/// @notice Deploys the full ConditionEngine + FSMInterpreter + ShredRegistry +
///         helpers behind ERC1967 proxies (matching production Deploy.s.sol),
///         registers ONE PDA whose authorizationId is supplied via env
///         (E2E_AUTHORIZATION_ID), and grants the deployer ORCHESTRATOR_ROLE +
///         OPERATOR_ROLE on the engine + OPERATOR_ROLE on the ShredRegistry so the
///         TypeScript E2E can drive authorizeReveal / requestShred / authorizeShred
///         / finalizeShred over RPC. Writes the deployed addresses + the computed
///         h_commit + pda_root to deployments/e2e-anvil.json for the test to read.
///
///         The PDA uses Mode P (predicate) on both axes, ShredAuthorityMode.Operator
///         (so the deployer's OPERATOR_ROLE can requestShred), and challengeWindow=0
///         on reveal (→ PostChallengeRevealInProgress, the off-chain combiner runs)
///         and the protocol shred floor on the shred axis.
///
///         RUN:
///           forge script script/E2EAnvil.s.sol:E2EAnvil --rpc-url http://127.0.0.1:8546 \
///             --broadcast --sig "run()" --private-key <anvilKey0>
///         with E2E_AUTHORIZATION_ID set.
contract E2EAnvil is Script {
    function run() external {
        bytes32 authorizationId = vm.envBytes32("E2E_AUTHORIZATION_ID");
        // A SECOND authorization registered for the SHRED test. The on-chain shred
        // axis (authorizeShred → finalizeShred → Shredded) requires the lifecycle
        // to be Registered (not RevealCompleted), so the shred test uses a fresh,
        // never-revealed authorization. Defaults to a fixed value if the env is
        // absent (the test always sets it).
        bytes32 shredAuthorizationId = vm.envOr(
            "E2E_SHRED_AUTHORIZATION_ID",
            bytes32(0x4400000000000000000000000000000000000000000000000000000000000044)
        );
        address deployer = msg.sender;

        vm.startBroadcast();

        CealisIdentifierHelpers helpers = new CealisIdentifierHelpers();
        AlwaysTrueModule module = new AlwaysTrueModule();

        // F-01: impls self-lock via _disableInitializers(); run behind ERC1967
        // proxies. The engine proxy address is circularly referenced by fsm/shred
        // at init time, so predict it the way production does. Deploy order from the
        // broadcaster (deployer) nonce captured here:
        //   helpers(+0), module(+1), fsm impl(+2), fsm proxy(+3), shred impl(+4),
        //   shred proxy(+5), engine impl(+6), engine proxy(+7).
        // helpers + module already consumed 2 nonces above; predict the engine proxy
        // at the deployer's CURRENT nonce + 5 (fsm impl, fsm proxy, shred impl,
        // shred proxy, engine impl, [engine proxy]).
        uint256 nonceBeforeFsm = vm.getNonce(deployer);
        address predictedEngine = vm.computeCreateAddress(deployer, nonceBeforeFsm + 5);

        FSMInterpreter fsm = FSMInterpreter(
            address(
                new ERC1967Proxy(
                    address(new FSMInterpreter()),
                    abi.encodeCall(FSMInterpreter.initialize, (deployer, predictedEngine))
                )
            )
        );
        ShredRegistry shred = ShredRegistry(
            address(
                new ERC1967Proxy(
                    address(new ShredRegistry()),
                    abi.encodeCall(ShredRegistry.initialize, (deployer, predictedEngine))
                )
            )
        );

        ConditionEngine.EngineConfig memory cfg;
        cfg.timelock = deployer;
        cfg.helpers = address(helpers);
        cfg.fsmInterpreter = address(fsm);
        cfg.shredRegistry = address(shred);
        cfg.conditionModules[0] = address(module);
        ConditionEngine engine = ConditionEngine(
            address(new ERC1967Proxy(address(new ConditionEngine()), abi.encodeCall(ConditionEngine.initialize, (cfg))))
        );
        require(address(engine) == predictedEngine, "engine proxy prediction drift");

        // Deployer is the timelock here (single-key local harness) → it already
        // holds DEFAULT_ADMIN_ROLE on the engine + shred. Grant the operational
        // roles the E2E driver needs.
        engine.grantRole(Roles.ORCHESTRATOR_ROLE, deployer);
        engine.grantRole(Roles.OPERATOR_ROLE, deployer);
        shred.grantRole(Roles.OPERATOR_ROLE, deployer);

        // Register the reveal PDA. Mode P on both axes pointing at the always-true
        // module; Operator shred authority (deployer holds OPERATOR_ROLE on shred).
        PDARegistration memory reg = _registration(helpers, address(module), authorizationId);
        bytes32 hCommit = helpers.computeHCommit(reg.hCommitFields);
        engine.registerPDA(reg);

        // Register the SHRED PDA (separate, never-revealed authorization).
        PDARegistration memory shredReg = _registration(helpers, address(module), shredAuthorizationId);
        bytes32 shredHCommit = helpers.computeHCommit(shredReg.hCommitFields);
        engine.registerPDA(shredReg);

        vm.stopBroadcast();

        // Emit + persist the addresses + computed h_commit / pda_root for the test.
        console2.log("E2E_CONDITION_ENGINE", address(engine));
        console2.log("E2E_SHRED_REGISTRY", address(shred));
        console2.log("E2E_FSM", address(fsm));
        console2.log("E2E_HELPERS", address(helpers));
        console2.logBytes32(hCommit);
        console2.logBytes32(reg.hCommitFields.pdaRoot);

        string memory json = "e2e";
        vm.serializeAddress(json, "conditionEngine", address(engine));
        vm.serializeAddress(json, "shredRegistry", address(shred));
        vm.serializeAddress(json, "fsmInterpreter", address(fsm));
        vm.serializeAddress(json, "helpers", address(helpers));
        vm.serializeBytes32(json, "authorizationId", authorizationId);
        vm.serializeBytes32(json, "hCommit", hCommit);
        vm.serializeBytes32(json, "pdaRoot", reg.hCommitFields.pdaRoot);
        vm.serializeBytes32(json, "shredAuthorizationId", shredAuthorizationId);
        string memory out = vm.serializeBytes32(json, "shredHCommit", shredHCommit);
        vm.writeJson(out, "./deployments/e2e-anvil.json");
    }

    // BR-D protocol floor (mirrors ConditionEngine.MIN_SHRED_LATENCY_FLOOR /
    // MIN_SHRED_CHALLENGE_WINDOW = 1 days). Operator (non-Disabled) authority must
    // satisfy both at registration.
    uint64 internal constant SHRED_LATENCY_FLOOR = 1 days;
    uint32 internal constant SHRED_WINDOW_FLOOR = 1 days;

    function _registration(CealisIdentifierHelpers helpers, address module, bytes32 authorizationId)
        internal
        view
        returns (PDARegistration memory reg)
    {
        reg.pdaRootFields = PdaRootFields({
            pdaId: keccak256("e2e-pda"),
            pdaVersion: 1,
            revealConditionMode: uint8(ConditionMode.ModeP),
            revealConditionSpecHash: keccak256("reveal-spec"),
            shredConditionMode: uint8(ConditionMode.ModeP),
            shredConditionSpecHash: keccak256("shred-spec"),
            oracleReferencesRoot: keccak256("oracle-root"),
            dslVersion: keccak256("dsl"),
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
            legalEffectExpected: false,
            cealisClassWideHaltOptOut: false,
            minimumShredLatency: SHRED_LATENCY_FLOOR,
            applicableJurisdiction: keccak256("DE"),
            conditionalRecipientsUpdatable: false,
            subjectLivenessRequiredAtFire: false,
            emergencyResponseBrickingAcknowledgment: true,
            timeCriticalPdaFlag: false,
            pdaUpdatable: false
        });

        bytes32 specHash = bytes32(uint256(uint160(module)));
        reg.revealAxis = AxisConfig({
            mode: ConditionMode.ModeP,
            conditionRef: keccak256("reveal-condition"),
            conditionSpecHash: specHash,
            challengeWindow: 0, // → PostChallengeRevealInProgress (off-chain combiner runs)
            eligibleChallengersRoot: keccak256("eligible-reveal"),
            resolverId: keccak256("resolver")
        });
        reg.shredAxis = AxisConfig({
            mode: ConditionMode.ModeP,
            conditionRef: keccak256("shred-condition"),
            conditionSpecHash: specHash,
            challengeWindow: SHRED_WINDOW_FLOOR,
            eligibleChallengersRoot: keccak256("eligible-shred"),
            resolverId: keccak256("resolver")
        });
        reg.legalFlags.requiredG4Phase = G4Phase.Phase2;
        reg.pauseAuthorityMode = PauseAuthorityMode.Partner;
        reg.shredGuardrailCompiled = true;
        reg.conditionalRecipientPolicyDigest = keccak256("recipient-policy");
        reg.conditionalRecipientModes = new ConditionalRecipientMode[](2);
        reg.conditionalRecipientModes[0] = ConditionalRecipientMode.PasskeyAccount;
        reg.conditionalRecipientModes[1] = ConditionalRecipientMode.WalletEOA;

        bytes32 pdaRoot = helpers.computePdaRoot(reg.pdaRootFields);
        reg.hCommitFields = HCommitFields({
            authorizationId: authorizationId,
            pdaRoot: pdaRoot,
            schemaDigest: keccak256("schema"),
            ciphertextDigest: keccak256("ciphertext"),
            aadDigest: keccak256("aad"),
            compositeIdentityDigest: keccak256("composite"),
            endpointAttestationDigest: keccak256("endpoint"),
            retentionWindow: 365 days,
            shredAuthorityId: bytes32(uint256(uint8(ShredAuthorityMode.Operator))),
            recipientsRoot: keccak256("recipients"),
            revealChallengeWindow: 0,
            shredChallengeWindow: SHRED_WINDOW_FLOOR,
            g3Choice: 1, // drand
            phase: uint8(G4Phase.Phase2),
            commitVersion: ProtocolVersion.BUILD_PROTOCOL_VERSION
        });
    }
}
