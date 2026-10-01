// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { ChallengeRegistry } from "../../src/challenge/ChallengeRegistry.sol";
import { CeremonyAxis } from "../../src/lib/Enums.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract ChallengeRegistryFuzzTest is Test {
    ChallengeRegistry internal cr;
    address internal timelock = address(0xA11CE);
    address internal orchestrator = address(0xB0B);

    function setUp() public {
        cr = ChallengeRegistry(
            ProxyDeploy.deployProxy(
                address(new ChallengeRegistry()), abi.encodeCall(ChallengeRegistry.initialize, (timelock))
            )
        );
        // Grant ORCHESTRATOR_ROLE to a known address
        vm.prank(timelock);
        cr.grantRole(Roles.ORCHESTRATOR_ROLE, orchestrator);
        vm.warp(1_000_000);
    }

    /// @notice Fuzz: openChallenge MUST revert ChallengeWindowZero for any
    ///         unconfigured (authorizationId, axis) regardless of caller.
    function testFuzz_openChallenge_RevertsForUnconfiguredKey(
        bytes32 authorizationId,
        uint8 axisRaw,
        bytes32 counterAttestationRef,
        uint256 bondAmount
    ) external {
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        vm.assume(counterAttestationRef != bytes32(0));
        bondAmount = bound(bondAmount, 1, 100 ether);
        vm.deal(address(this), bondAmount);
        vm.expectRevert(abi.encodeWithSelector(ChallengeRegistry.ChallengeWindowZero.selector, authorizationId, axis));
        cr.openChallenge{ value: bondAmount }(
            authorizationId, axis, ChallengeRegistry.ChallengeReason.OracleAttestationDisputed,
            counterAttestationRef, bondAmount, new bytes32[](0)
        );
    }

    /// @notice Fuzz: configureChallenge MUST revert for any non-ORCHESTRATOR caller.
    function testFuzz_configureChallenge_UnauthorizedRevert(
        address stranger,
        bytes32 authorizationId,
        uint8 axisRaw,
        uint64 windowEnd,
        uint256 requiredBond
    ) external {
        vm.assume(stranger != address(0));
        vm.assume(stranger != orchestrator);
        vm.assume(stranger != timelock);
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        vm.prank(stranger);
        vm.expectRevert(); // AccessControl rejects non-orchestrator
        cr.configureChallenge(
            authorizationId, axis, windowEnd, requiredBond, bytes32(0), address(0), address(0), 0, address(0xBEEF)
        );
    }

    /// @notice Fuzz: any valid config write succeeds with ORCHESTRATOR_ROLE.
    function testFuzz_configureChallenge_AcceptsAnyValidArgs(
        bytes32 authorizationId,
        uint8 axisRaw,
        uint64 windowEnd,
        uint256 requiredBond,
        bytes32 eligibleChallengersRoot,
        address eligibleCaller,
        address resolver,
        uint8 maxExtensions
    ) external {
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        // ConfigureChallenge accepts ANY args (validation lives at openChallenge time)
        vm.prank(orchestrator);
        cr.configureChallenge(
            authorizationId, axis, windowEnd, requiredBond, eligibleChallengersRoot,
            eligibleCaller, resolver, maxExtensions, address(0xBEEF)
        );
        // No revert = pass; we don't query stored state here (private struct mapping)
    }

    /// @notice Fuzz: openChallenge MUST revert ChallengeWindowClosed for any
    ///         (now > windowEnd) regardless of other args.
    function testFuzz_openChallenge_RevertsAfterWindowClose(
        bytes32 authorizationId,
        uint8 axisRaw,
        uint32 windowSize,
        uint32 jumpPast,
        bytes32 counterAttestationRef
    ) external {
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        vm.assume(counterAttestationRef != bytes32(0));
        uint64 windowEnd = uint64(block.timestamp) + uint64(windowSize) + 1;
        // Configure with reasonable values
        vm.prank(orchestrator);
        cr.configureChallenge(
            authorizationId, axis, windowEnd, 0, bytes32(0), address(0), address(0xCAFE), 0, address(0xBEEF)
        );
        // Jump past windowEnd
        vm.warp(uint256(windowEnd) + uint256(jumpPast) + 1);
        vm.expectRevert(abi.encodeWithSelector(ChallengeRegistry.ChallengeWindowClosed.selector, authorizationId, axis));
        cr.openChallenge(
            authorizationId, axis, ChallengeRegistry.ChallengeReason.IntegrityClaim,
            counterAttestationRef, 0, new bytes32[](0)
        );
    }

    /// @notice Fuzz: openChallenge MUST revert ChallengeBondTooLow when msg.value < requiredBond.
    function testFuzz_openChallenge_RevertsOnInsufficientBond(
        bytes32 authorizationId,
        uint8 axisRaw,
        uint256 requiredBond,
        uint256 providedBond,
        bytes32 counterAttestationRef
    ) external {
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        vm.assume(counterAttestationRef != bytes32(0));
        requiredBond = bound(requiredBond, 1, 100 ether);
        providedBond = bound(providedBond, 0, requiredBond - 1);

        uint64 windowEnd = uint64(block.timestamp) + 1 days;
        vm.prank(orchestrator);
        cr.configureChallenge(
            authorizationId, axis, windowEnd, requiredBond, bytes32(0), address(0), address(0xCAFE), 0, address(0xBEEF)
        );
        vm.deal(address(this), providedBond);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChallengeRegistry.ChallengeBondTooLow.selector, authorizationId, requiredBond, providedBond
            )
        );
        cr.openChallenge{ value: providedBond }(
            authorizationId, axis, ChallengeRegistry.ChallengeReason.LegalHoldAsserted,
            counterAttestationRef, requiredBond, new bytes32[](0)
        );
    }

    /// @notice Fuzz: openChallenge MUST revert ChallengeCounterAttestationMalformed
    ///         for any zero counterAttestationRef.
    function testFuzz_openChallenge_RevertsOnZeroCounterRef(
        bytes32 authorizationId,
        uint8 axisRaw,
        uint8 reasonRaw,
        uint256 bondAmount
    ) external {
        CeremonyAxis axis = CeremonyAxis(axisRaw % 2);
        ChallengeRegistry.ChallengeReason reason = ChallengeRegistry.ChallengeReason(reasonRaw % 6);
        bondAmount = bound(bondAmount, 0, 100 ether);

        uint64 windowEnd = uint64(block.timestamp) + 1 days;
        vm.prank(orchestrator);
        cr.configureChallenge(
            authorizationId, axis, windowEnd, 0, bytes32(0), address(0), address(0xCAFE), 0, address(0xBEEF)
        );
        vm.deal(address(this), bondAmount);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChallengeRegistry.ChallengeCounterAttestationMalformed.selector, authorizationId, bytes32(0)
            )
        );
        cr.openChallenge{ value: bondAmount }(authorizationId, axis, reason, bytes32(0), 0, new bytes32[](0));
    }
}
