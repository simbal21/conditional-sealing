// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { ConditionEngine } from "../../src/engine/ConditionEngine.sol";
import { IConditionEngine, IConditionModule } from "../../src/engine/IConditionEngine.sol";
import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import {
    CeremonyAxis,
    ConditionMode,
    LifecycleState,
    ShredAuthorityMode
} from "../../src/lib/Enums.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { DeprecationFlag, PDARegistration } from "../../src/lib/Structs.sol";
import { ConditionEngineTestBase } from "./ConditionEngine.t.sol";

/// @notice Attacker-controlled module NOT wired into the engine's _conditionModules.
contract RogueModule is IConditionModule {
    function configure(bytes32, bytes32, bytes calldata) external { }

    function advance(bytes32, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }

    function evaluate(bytes32, bytes32) external pure returns (bool) {
        return true; // unconditionally true — the bypass primitive
    }
}

/// @notice Minimal ChallengeRegistry mock exposing only the engine read surface.
contract MockChallengeRegistry {
    // ChallengeRegistry.ChallengeStatus: None,Open,ConfirmedNoIntervention,Halted,Expired,Withdrawn,Dismissed
    mapping(bytes32 => uint8) private _status;

    function _key(bytes32 authorizationId, CeremonyAxis axis) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(authorizationId, uint8(axis)));
    }

    function setStatus(bytes32 authorizationId, CeremonyAxis axis, uint8 status) external {
        _status[_key(authorizationId, axis)] = status;
    }

    function challengeStatus(bytes32 authorizationId, CeremonyAxis axis) external view returns (uint8) {
        return _status[_key(authorizationId, axis)];
    }
}

/// @notice Registry mock whose getEntryAt reverts at/after a tombstone block but
///         succeeds for earlier blocks — models post-authorization tombstoning.
contract TombstoneRegistry is IBaseRegistry {
    uint64 public tombstoneBlock = type(uint64).max;

    function setTombstone(uint64 blockNumber) external {
        tombstoneBlock = blockNumber;
    }

    function deprecationFlag(bytes32) external pure returns (DeprecationFlag memory flag) {
        return flag;
    }

    function getEntry(bytes32) external pure returns (bytes memory) {
        return hex"01";
    }

    function getEntryAt(bytes32 id, uint64 blockNumber) external view returns (bytes memory) {
        if (blockNumber >= tombstoneBlock) revert RegistryEntryTombstoned(id, blockNumber);
        return hex"01";
    }

    function publishDisclosure(bytes32, bytes calldata) external { }
    function triggerAutoClear(bytes32) external { }
}

contract ConditionEngineAdversarialTest is ConditionEngineTestBase {
    /// @notice B3b (HIGH): a registration pointing the Mode-P condition at an
    ///         attacker-controlled contract (whose evaluate() returns true) MUST
    ///         NOT authorize a reveal. Against the vulnerable code (only
    ///         code.length != 0, no _conditionModules membership) the rogue module
    ///         would fire RevealAuthorized — a full authorization bypass.
    function test_B3b_authorizeReveal_RejectsNonWhitelistedModule() external {
        RogueModule rogue = new RogueModule();
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        // Point the reveal condition at the rogue (non-registered) module.
        reg.revealAxis.conditionSpecHash = bytes32(uint256(uint160(address(rogue))));
        bytes32 pdaRoot = helpers.computePdaRoot(reg.pdaRootFields);
        reg.hCommitFields.pdaRoot = pdaRoot;
        _register(reg);

        vm.expectRevert(
            abi.encodeWithSelector(IConditionEngine.ConditionNotMet.selector, auth, CeremonyAxis.Reveal)
        );
        engine.authorizeReveal(auth, evidence);
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.Registered));
    }

    /// @notice B3b control: the engine-registered module (wired at initialize) still
    ///         authorizes normally — the membership check is not over-broad.
    function test_B3b_authorizeReveal_RegisteredModuleStillWorks() external {
        PDARegistration memory reg = _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        _register(reg);
        engine.authorizeReveal(auth, evidence);
        assertTrue(engine.canGatesSign(auth));
    }
}

/// @notice F-2 + BR-H + BR-D tests need a freshly-wired engine (ChallengeRegistry,
///         registry refs) so we build the engine directly rather than via the base.
contract ConditionEngineWiredAdversarialTest is ConditionEngineTestBase {
    MockChallengeRegistry internal challenge;
    TombstoneRegistry internal pluginRegistry;

    function _buildEngineWith(ConditionEngine.EngineConfig memory config) internal returns (ConditionEngine e) {
        ConditionEngine impl = new ConditionEngine();
        bytes memory init = abi.encodeCall(ConditionEngine.initialize, (config));
        e = ConditionEngine(address(new ERC1967Proxy(address(impl), init)));
        vm.startPrank(timelock);
        e.grantRole(Roles.ORCHESTRATOR_ROLE, orchestrator);
        e.grantRole(Roles.OPERATOR_ROLE, operator);
        vm.stopPrank();
    }

    // ── F-2: markChallengeResolved must not stomp a live challenge ──────────────

    /// @notice F-2 (HIGH): with a challenge still Open in the bound
    ///         ChallengeRegistry, OPERATOR cannot force post-challenge reveal.
    ///         Vulnerable code forced PostChallengeRevealInProgress unconditionally.
    function test_F2_markChallengeResolved_RevertsWhileChallengeOpen() external {
        challenge = new MockChallengeRegistry();
        ConditionEngine.EngineConfig memory config;
        config.timelock = timelock;
        config.helpers = address(helpers);
        config.fsmInterpreter = address(fsm);
        config.challengeRegistry = address(challenge);
        config.conditionModules[0] = address(module);
        ConditionEngine e = _buildEngineWith(config);

        PDARegistration memory reg = _validRegistrationWith(
            auth, ConditionMode.ModeP, ConditionMode.ModeP, 1 days, 1 days, ShredAuthorityMode.Subject
        );
        vm.prank(orchestrator);
        e.registerPDA(reg);
        e.authorizeReveal(auth, evidence);
        assertEq(uint8(e.lifecycleState(auth)), uint8(LifecycleState.RevealChallengeOpen));

        // A legitimate challenge is Open (status index 1). Even past the window,
        // the override is hard-blocked until the resolver acts.
        challenge.setStatus(auth, CeremonyAxis.Reveal, 1);
        vm.warp(block.timestamp + 2 days);
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConditionEngine.ConditionChallengeStillOpen.selector, auth, CeremonyAxis.Reveal
            )
        );
        e.markChallengeResolved(auth, CeremonyAxis.Reveal);
        assertEq(uint8(e.lifecycleState(auth)), uint8(LifecycleState.RevealChallengeOpen));
    }

    /// @notice F-2: within the window and with no open challenge, the override
    ///         still cannot fire (window must elapse). Vulnerable code allowed it.
    function test_F2_markChallengeResolved_RevertsBeforeWindowElapses() external {
        ConditionEngine.EngineConfig memory config;
        config.timelock = timelock;
        config.helpers = address(helpers);
        config.fsmInterpreter = address(fsm);
        config.conditionModules[0] = address(module);
        ConditionEngine e = _buildEngineWith(config);

        PDARegistration memory reg = _validRegistrationWith(
            auth, ConditionMode.ModeP, ConditionMode.ModeP, 1 days, 1 days, ShredAuthorityMode.Subject
        );
        vm.prank(orchestrator);
        e.registerPDA(reg);
        e.authorizeReveal(auth, evidence);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConditionEngine.ConditionChallengeNotResolved.selector, auth, CeremonyAxis.Reveal
            )
        );
        e.markChallengeResolved(auth, CeremonyAxis.Reveal);
    }

    /// @notice F-2 positive: resolver ConfirmedNoIntervention (status 2) clears the
    ///         challenge even before the window elapses.
    function test_F2_markChallengeResolved_AllowedOnConfirmedNoIntervention() external {
        challenge = new MockChallengeRegistry();
        ConditionEngine.EngineConfig memory config;
        config.timelock = timelock;
        config.helpers = address(helpers);
        config.fsmInterpreter = address(fsm);
        config.challengeRegistry = address(challenge);
        config.conditionModules[0] = address(module);
        ConditionEngine e = _buildEngineWith(config);

        PDARegistration memory reg = _validRegistrationWith(
            auth, ConditionMode.ModeP, ConditionMode.ModeP, 1 days, 1 days, ShredAuthorityMode.Subject
        );
        vm.prank(orchestrator);
        e.registerPDA(reg);
        e.authorizeReveal(auth, evidence);

        challenge.setStatus(auth, CeremonyAxis.Reveal, 2); // ConfirmedNoIntervention
        vm.prank(operator);
        e.markChallengeResolved(auth, CeremonyAxis.Reveal);
        assertEq(uint8(e.lifecycleState(auth)), uint8(LifecycleState.PostChallengeRevealInProgress));
    }

    /// @notice F-2 positive: window elapsed + no open challenge → override allowed.
    function test_F2_markChallengeResolved_AllowedAfterWindowNoChallenge() external {
        ConditionEngine.EngineConfig memory config;
        config.timelock = timelock;
        config.helpers = address(helpers);
        config.fsmInterpreter = address(fsm);
        config.conditionModules[0] = address(module);
        ConditionEngine e = _buildEngineWith(config);

        PDARegistration memory reg = _validRegistrationWith(
            auth, ConditionMode.ModeP, ConditionMode.ModeP, 1 days, 1 days, ShredAuthorityMode.Subject
        );
        vm.prank(orchestrator);
        e.registerPDA(reg);
        e.authorizeReveal(auth, evidence);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(operator);
        e.markChallengeResolved(auth, CeremonyAxis.Reveal);
        assertEq(uint8(e.lifecycleState(auth)), uint8(LifecycleState.PostChallengeRevealInProgress));
    }

    // ── BR-H: registry reads anchored at registration block, not block.number ───

    /// @notice BR-H (MEDIUM): a registry entry tombstoned AFTER authorization must
    ///         not retroactively break an in-flight ceremony. The engine reads at
    ///         the PDA registration block. Vulnerable code read at block.number and
    ///         reverted the reveal.
    function test_BRH_registryReadAtRegistrationBlock_NotCurrent() external {
        pluginRegistry = new TombstoneRegistry();
        ConditionEngine.EngineConfig memory config;
        config.timelock = timelock;
        config.helpers = address(helpers);
        config.fsmInterpreter = address(fsm);
        config.pluginHashRegistry = address(pluginRegistry);
        config.conditionModules[0] = address(module);
        ConditionEngine e = _buildEngineWith(config);

        PDARegistration memory reg =
            _validRegistration(ConditionMode.ModeP, ConditionMode.ModeP);
        // Bind a non-zero plugin ref so _registryReadAt actually probes the registry.
        reg.registryRefs.pluginVersionDigest = keccak256("plugin-v1");
        vm.prank(orchestrator);
        e.registerPDA(reg);
        uint64 regBlock = uint64(block.number);

        // Tombstone the plugin entry at a LATER block, then advance the chain past it.
        pluginRegistry.setTombstone(regBlock + 5);
        vm.roll(regBlock + 10);

        // Reading at block.number (vulnerable) would revert RegistryEntryTombstoned;
        // reading at regBlock (fixed) succeeds. Reveal must proceed.
        e.authorizeReveal(auth, evidence);
        assertTrue(e.canGatesSign(auth));
    }

    // ── BR-D: minimum shred latency + window floor on non-Disabled PDAs ─────────

    /// @notice BR-D (MEDIUM): a non-Disabled shred-authority PDA with latency=0 +
    ///         window=0 MUST be rejected at registration. Vulnerable code accepted
    ///         it → a compromised ORCHESTRATOR could register hostile immediate-shred
    ///         PDAs.
    function test_BRD_registerPDA_RejectsZeroLatencyOnNonDisabledShred() external {
        // Hand-build a registration that bypasses the helper's floor clamping.
        PDARegistration memory reg = _validRegistrationWith(
            auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Disabled
        );
        // Flip authority to Subject (non-Disabled) while keeping latency/window 0.
        reg.pdaRootFields.minimumShredLatency = 0;
        reg.hCommitFields.shredAuthorityId = bytes32(uint256(uint8(ShredAuthorityMode.Subject)));
        reg.shredAxis.challengeWindow = 0;
        reg.hCommitFields.shredChallengeWindow = 0;
        reg.hCommitFields.pdaRoot = helpers.computePdaRoot(reg.pdaRootFields);

        vm.prank(orchestrator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConditionEngine.ConditionShredLatencyBelowFloor.selector, auth, uint64(0), uint64(1 days)
            )
        );
        engine.registerPDA(reg);
    }

    /// @notice BR-D control: Disabled shred-authority PDAs (permanent archival /
    ///         testament) are exempt — no shred path, so the floor does not apply.
    function test_BRD_registerPDA_AllowsZeroLatencyOnDisabledShred() external {
        PDARegistration memory reg = _validRegistrationWith(
            auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Disabled
        );
        // Disabled path: helper leaves latency/window at 0; registration must pass.
        assertEq(reg.pdaRootFields.minimumShredLatency, 0);
        _register(reg);
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.Registered));
    }
}
