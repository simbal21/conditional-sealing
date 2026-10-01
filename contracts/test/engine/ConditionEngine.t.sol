// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { ConditionEngine } from "../../src/engine/ConditionEngine.sol";
import { IConditionEngine, IConditionModule } from "../../src/engine/IConditionEngine.sol";
import { FSMInterpreter } from "../../src/fsm/FSMInterpreter.sol";
import { CealisIdentifierHelpers } from "../../src/helpers/CealisIdentifierHelpers.sol";
import {
    CeremonyAxis,
    ConditionMode,
    ConditionalRecipientMode,
    G4Phase,
    LifecycleState,
    PauseAuthorityMode,
    ProtocolVersion,
    ShredAuthorityMode,
    ShredState
} from "../../src/lib/Enums.sol";
import { BuildProtocolVersionMismatch, LegalEffectSyncedPasskeyForbidden } from "../../src/lib/Errors.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { AxisConfig, HCommitFields, PDARegistration, PdaRootFields } from "../../src/lib/Structs.sol";
import { ShredRegistry } from "../../src/shred/ShredRegistry.sol";

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

abstract contract ConditionEngineTestBase is Test {
    ConditionEngine internal engine;
    ShredRegistry internal shred;
    FSMInterpreter internal fsm;
    CealisIdentifierHelpers internal helpers;
    AlwaysTrueModule internal module;

    address internal timelock = address(0xA001);
    address internal orchestrator = address(0xA002);
    address internal operator = address(0xA003);
    address internal subject = address(0xA004);
    bytes32 internal auth = keccak256("authorization");
    bytes32 internal evidence = keccak256("evidence");

    event PDARegistered(
        bytes32 indexed authorizationId, bytes32 indexed hCommit, bytes32 indexed pdaRoot, bytes32 partnerId
    );
    event RevealAuthorized(
        bytes32 indexed authorizationId,
        bytes32 indexed hCommit,
        bytes32 indexed pdaRoot,
        uint64 authorizationBlock,
        uint64 authorizationTimestamp,
        uint32 challengeWindow,
        bytes32 conditionRef
    );
    event ShredAuthorized(
        bytes32 indexed authorizationId,
        bytes32 indexed hCommit,
        bytes32 indexed pdaRoot,
        uint64 authorizationBlock,
        uint64 authorizationTimestamp,
        uint32 challengeWindow,
        bytes32 conditionRef
    );
    event LifecycleStateChanged(bytes32 indexed authorizationId, LifecycleState oldState, LifecycleState newState);

    function setUp() public virtual {
        vm.warp(1_000_000);
        helpers = new CealisIdentifierHelpers();
        module = new AlwaysTrueModule();

        // F-01: impls now self-lock via `_disableInitializers()`, so the engine,
        // fsm and shred must run behind ERC1967 proxies (matching production
        // `Deploy.s.sol`). The engine proxy address is circularly referenced by
        // fsm/shred at init time, so predict it the same way production does.
        //
        // Deploy order below from this contract's account, counted from the nonce
        // captured here: fsm impl (+0), fsm proxy (+1), shred impl (+2),
        // shred proxy (+3), engine impl (+4), engine proxy (+5).
        uint256 nonceBeforeFsm = vm.getNonce(address(this));
        address predictedEngine = vm.computeCreateAddress(address(this), nonceBeforeFsm + 5);

        fsm = FSMInterpreter(
            address(new ERC1967Proxy(address(new FSMInterpreter()), abi.encodeCall(FSMInterpreter.initialize, (timelock, predictedEngine))))
        );
        shred = ShredRegistry(
            address(new ERC1967Proxy(address(new ShredRegistry()), abi.encodeCall(ShredRegistry.initialize, (timelock, predictedEngine))))
        );

        ConditionEngine.EngineConfig memory config;
        config.timelock = timelock;
        config.helpers = address(helpers);
        config.fsmInterpreter = address(fsm);
        config.shredRegistry = address(shred);
        config.conditionModules[0] = address(module);
        engine = ConditionEngine(
            address(new ERC1967Proxy(address(new ConditionEngine()), abi.encodeCall(ConditionEngine.initialize, (config))))
        );
        require(address(engine) == predictedEngine, "engine proxy prediction drift");

        vm.startPrank(timelock);
        engine.grantRole(Roles.ORCHESTRATOR_ROLE, orchestrator);
        engine.grantRole(Roles.OPERATOR_ROLE, operator);
        shred.grantRole(Roles.OPERATOR_ROLE, operator);
        vm.stopPrank();
    }

    function _register(PDARegistration memory reg) internal returns (bytes32 hCommit) {
        hCommit = helpers.computeHCommit(reg.hCommitFields);
        vm.prank(orchestrator);
        engine.registerPDA(reg);
    }

    function _validRegistration(ConditionMode revealMode, ConditionMode shredMode)
        internal
        view
        returns (PDARegistration memory reg)
    {
        return _validRegistrationWith(auth, revealMode, shredMode, 0, 0, ShredAuthorityMode.Subject);
    }

    // BR-D: protocol floor mirrors ConditionEngine.MIN_SHRED_LATENCY_FLOOR /
    // MIN_SHRED_CHALLENGE_WINDOW (1 days). Non-Disabled shred-authority PDAs must
    // satisfy both at registration. The helper raises both to the floor for
    // non-Disabled authorities so existing registrations remain valid; tests that
    // need an exact value pass a value >= floor.
    uint64 internal constant SHRED_LATENCY_FLOOR = 1 days;
    uint32 internal constant SHRED_WINDOW_FLOOR = 1 days;

    function _validRegistrationWith(
        bytes32 authorizationId,
        ConditionMode revealMode,
        ConditionMode shredMode,
        uint32 revealWindow,
        uint32 shredWindow,
        ShredAuthorityMode authorityMode
    ) internal view returns (PDARegistration memory reg) {
        // BR-D floor: clamp shred latency + window up for non-Disabled authorities.
        bool shredActive = authorityMode != ShredAuthorityMode.Disabled && authorityMode != ShredAuthorityMode.None;
        uint64 shredLatency = 0;
        if (shredActive) {
            shredLatency = SHRED_LATENCY_FLOOR;
            if (shredWindow < SHRED_WINDOW_FLOOR) shredWindow = SHRED_WINDOW_FLOOR;
        }
        reg.pdaRootFields = PdaRootFields({
            pdaId: keccak256("pda"),
            pdaVersion: 1,
            revealConditionMode: uint8(revealMode),
            revealConditionSpecHash: keccak256("reveal-spec"),
            shredConditionMode: uint8(shredMode),
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
            minimumShredLatency: shredLatency,
            applicableJurisdiction: keccak256("DE"),
            conditionalRecipientsUpdatable: false,
            subjectLivenessRequiredAtFire: false,
            emergencyResponseBrickingAcknowledgment: true,
            timeCriticalPdaFlag: false,
            pdaUpdatable: false
        });

        bytes32 revealSpec =
            revealMode == ConditionMode.ModeP ? bytes32(uint256(uint160(address(module)))) : keccak256("fsm-reveal");
        bytes32 shredSpec =
            shredMode == ConditionMode.ModeP ? bytes32(uint256(uint160(address(module)))) : keccak256("fsm-shred");
        reg.revealAxis = AxisConfig({
            mode: revealMode,
            conditionRef: keccak256("reveal-condition"),
            conditionSpecHash: revealSpec,
            challengeWindow: revealWindow,
            eligibleChallengersRoot: keccak256("eligible-reveal"),
            resolverId: keccak256("resolver")
        });
        reg.shredAxis = AxisConfig({
            mode: shredMode,
            conditionRef: keccak256("shred-condition"),
            conditionSpecHash: shredSpec,
            challengeWindow: shredWindow,
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
            shredAuthorityId: bytes32(uint256(uint8(authorityMode))),
            recipientsRoot: keccak256("recipients"),
            revealChallengeWindow: revealWindow,
            shredChallengeWindow: shredWindow,
            g3Choice: 0,
            phase: uint8(G4Phase.Phase2),
            commitVersion: ProtocolVersion.BUILD_PROTOCOL_VERSION
        });
    }

    function _corruptPauseAuthorityCalldata(PDARegistration memory reg) internal pure returns (bytes memory data) {
        data = abi.encodeCall(IConditionEngine.registerPDA, (reg));
        uint256 byteOffset = 4 + 32 + (71 * 32) + 31;
        assembly {
            mstore8(add(add(data, 32), byteOffset), 3)
        }
    }
}

contract ConditionEngineTest is ConditionEngineTestBase {
    function test_registerPDA_PositiveCaseEmitsAndStores() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        bytes32 hCommit = helpers.computeHCommit(reg.hCommitFields);

        vm.expectEmit(true, true, true, true, address(engine));
        emit PDARegistered(auth, hCommit, reg.hCommitFields.pdaRoot, reg.pdaRootFields.partnerId);
        vm.expectEmit(true, false, false, true, address(engine));
        emit LifecycleStateChanged(auth, LifecycleState.Unregistered, LifecycleState.Registered);
        _register(reg);
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.Registered));
        assertEq(engine.hCommitForAuthorization(auth), hCommit);
    }

    function test_registerPDA_RevertsOnMode3AtEveryArrayPosition() external {
        for (uint256 i = 0; i < 2; ++i) {
            PDARegistration memory reg = _validRegistrationWith(
                keccak256(abi.encodePacked("auth", i)),
                ConditionMode.ModeP,
                ConditionMode.ModeP,
                0,
                0,
                ShredAuthorityMode.Subject
            );
            reg.hCommitFields.authorizationId = keccak256(abi.encodePacked("auth", i));
            reg.conditionalRecipientModes[i] = ConditionalRecipientMode.WalletEIP1271Reserved;
            vm.prank(orchestrator);
            vm.expectRevert(
                abi.encodeWithSelector(
                    IConditionEngine.ConditionMode3Reserved.selector, reg.hCommitFields.authorizationId
                )
            );
            engine.registerPDA(reg);
        }
    }

    function test_registerPDA_RevertsLegalEffectHaltOptOut() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        reg.legalFlags.legalEffectExpected = true;
        reg.pdaRootFields.legalEffectExpected = true;
        reg.pdaRootFields.cealisClassWideHaltOptOut = true;
        reg.hCommitFields.pdaRoot = helpers.computePdaRoot(reg.pdaRootFields);
        vm.prank(orchestrator);
        vm.expectRevert(abi.encodeWithSelector(IConditionEngine.ConditionLegalEffectHaltOptOutForbidden.selector, auth));
        engine.registerPDA(reg);
    }

    function test_registerPDA_RevertsLegalEffectPhase1G4() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        reg.legalFlags.legalEffectExpected = true;
        reg.legalFlags.requiredG4Phase = G4Phase.Phase1;
        vm.prank(orchestrator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IConditionEngine.ConditionLegalEffectPhaseInvalid.selector, auth, uint8(G4Phase.Phase1)
            )
        );
        engine.registerPDA(reg);
    }

    function test_registerPDA_RevertsLegalEffectSyncedPasskey() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        reg.legalFlags.legalEffectExpected = true;
        reg.legalFlags.subjectAuthenticatorClass = 0x03;
        vm.prank(orchestrator);
        vm.expectRevert(abi.encodeWithSelector(LegalEffectSyncedPasskeyForbidden.selector, auth));
        engine.registerPDA(reg);
    }

    function test_registerPDA_RevertsInvalidCommitVersion() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        reg.hCommitFields.commitVersion = 0x0301;
        vm.prank(orchestrator);
        vm.expectRevert(abi.encodeWithSelector(BuildProtocolVersionMismatch.selector, uint16(0x0301), uint16(0x0302)));
        engine.registerPDA(reg);
    }

    function test_registerPDA_RevertsInvalidPauseAuthorityFromCalldata() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        bytes memory data = _corruptPauseAuthorityCalldata(reg);
        vm.prank(orchestrator);
        (bool ok, bytes memory revertData) = address(engine).call(data);
        revertData;
        assertFalse(ok);
    }

    function test_registerPDA_RevertsMissingShredGuardrail() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        reg.shredGuardrailCompiled = false;
        vm.prank(orchestrator);
        vm.expectRevert(abi.encodeWithSelector(IConditionEngine.ConditionShredGuardrailMissing.selector, auth));
        engine.registerPDA(reg);
    }

    function test_registerPDA_RevertsPdaRootMismatchAndAlwaysRecomputes() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        reg.hCommitFields.pdaRoot = keccak256("caller-supplied-hash-only-root");
        bytes32 computed = helpers.computePdaRoot(reg.pdaRootFields);
        vm.prank(orchestrator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IConditionEngine.ConditionHCommitPdaRootMismatch.selector, reg.hCommitFields.pdaRoot, computed
            )
        );
        engine.registerPDA(reg);
    }

    function test_authorizeReveal_ModePEmitsRevealAuthorized() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        bytes32 hCommit = _register(reg);

        vm.expectEmit(true, true, true, true, address(engine));
        emit RevealAuthorized(
            auth,
            hCommit,
            reg.hCommitFields.pdaRoot,
            uint64(block.number),
            uint64(block.timestamp),
            0,
            reg.revealAxis.conditionRef
        );
        engine.authorizeReveal(auth, evidence);
        assertTrue(engine.canGatesSign(auth));
    }

    function test_authorizeReveal_ModeFTriggersFSMAndEmits() external {
        // F-1: Mode F now requires the FSM to be driven to its committed terminal
        // state through a REAL submitter-supplied transitionProof whose edge is a
        // member of the fsmHash-committed transition set. The engine no longer
        // fabricates a 0→1 terminal advance.
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeF, ConditionMode.ModeP);
        _register(reg);
        bytes32 fsmHash = reg.revealAxis.conditionSpecHash;
        bytes32 transitionId = keccak256("t01");
        vm.startPrank(timelock);
        fsm.configureFSM(auth, CeremonyAxis.Reveal, fsmHash, 0, 1, 1, 0, bytes32(0));
        // Single-edge FSM: edgeRoot IS the one legal edge leaf.
        fsm.configureFSMEdges(auth, CeremonyAxis.Reveal, fsm.edgeLeaf(fsmHash, 0, 1, transitionId));
        vm.stopPrank();

        bytes memory proof = abi.encode(
            FSMInterpreter.TransitionProof({
                fsmHash: fsmHash,
                fromState: 0,
                toState: 1,
                terminalState: 1,
                maxTransitions: 1,
                allowedSubmitter: address(0),
                conditionRef: reg.revealAxis.conditionRef,
                deadline: 0,
                edgeProof: new bytes32[](0)
            })
        );
        engine.advanceFSM(auth, CeremonyAxis.Reveal, transitionId, keccak256("attest"), proof);
        assertEq(fsm.currentState(auth, CeremonyAxis.Reveal), 1);
        assertTrue(fsm.isTerminal(auth, CeremonyAxis.Reveal));

        engine.authorizeReveal(auth, evidence);
        assertTrue(engine.canGatesSign(auth));
    }

    function test_authorizeShred_EmitsAndInformsShredRegistry() external {
        // BR-D: Subject (non-Disabled) authority now carries the protocol shred
        // window/latency floor, so the emitted window is SHRED_WINDOW_FLOOR and the
        // ShredRegistry enters ChallengeOpen (not immediate Authorized).
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        bytes32 hCommit = _register(reg);
        vm.expectEmit(true, true, true, true, address(engine));
        emit ShredAuthorized(
            auth,
            hCommit,
            reg.hCommitFields.pdaRoot,
            uint64(block.number),
            uint64(block.timestamp),
            SHRED_WINDOW_FLOOR,
            reg.shredAxis.conditionRef
        );
        engine.authorizeShred(auth, evidence);
        assertEq(uint8(shred.currentShredState(hCommit)), uint8(ShredState.ChallengeOpen));
    }

    function test_pauseAndUpgradeAuthorization() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        _register(reg);
        vm.prank(timelock);
        engine.pause(auth, uint64(block.timestamp + 1 hours), keccak256("pause"));
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.Paused));

        ConditionEngine implementation = new ConditionEngine();
        ConditionEngine.EngineConfig memory config;
        config.timelock = timelock;
        config.helpers = address(helpers);
        bytes memory init = abi.encodeCall(ConditionEngine.initialize, (config));
        address proxy = address(new ERC1967Proxy(address(implementation), init));
        ConditionEngine newImplementation = new ConditionEngine();
        vm.expectRevert();
        ConditionEngine(proxy).upgradeToAndCall(address(newImplementation), "");
    }
}
