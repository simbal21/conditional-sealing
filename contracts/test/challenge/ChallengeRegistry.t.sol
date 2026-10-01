// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { ChallengeRegistry } from "../../src/challenge/ChallengeRegistry.sol";
import { CeremonyAxis, PauseConstants } from "../../src/lib/Enums.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { IPausableSurface } from "../../src/base/IPausableSurface.sol";
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract ChallengeRegistryTest is Test {
    ChallengeRegistry internal registry;

    address internal timelock = address(0x8001);
    address internal orchestrator = address(0x8002);
    address internal challenger = address(0x8003);
    address internal resolver = address(0x8004);
    address internal otherResolver = address(0x8005);
    address internal treasury = address(0x8006);
    address internal stranger = address(0x8007);

    bytes32 internal auth = keccak256("auth");

    // Empty proof used on the unconstrained-allowlist path (eligibleChallengersRoot == 0).
    bytes32[] internal noProof;

    function setUp() public {
        vm.warp(1_000_000);
        registry = ChallengeRegistry(
            ProxyDeploy.deployProxy(
                address(new ChallengeRegistry()), abi.encodeCall(ChallengeRegistry.initialize, (timelock))
            )
        );
        vm.startPrank(timelock);
        registry.grantRole(Roles.ORCHESTRATOR_ROLE, orchestrator);
        registry.grantRole(Roles.CHALLENGE_RESOLVER_ROLE, resolver);
        registry.grantRole(Roles.CHALLENGE_RESOLVER_ROLE, otherResolver);
        vm.stopPrank();
        vm.deal(challenger, 10 ether);
        vm.deal(stranger, 10 ether);
    }

    function test_openChallengeRequiresMinimumBond() external {
        _configureNoRoot(auth, uint64(block.timestamp + 1 days), 1 ether, challenger, resolver, 1);
        vm.prank(challenger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChallengeRegistry.ChallengeBondTooLow.selector, auth, uint256(1 ether), uint256(0.5 ether)
            )
        );
        registry.openChallenge{ value: 0.5 ether }(
            auth,
            CeremonyAxis.Reveal,
            ChallengeRegistry.ChallengeReason.IntegrityClaim,
            keccak256("counter"),
            0.5 ether,
            noProof
        );
    }

    function test_zeroWindowTierAReverts() external {
        _configureNoRoot(auth, 0, 0, challenger, resolver, 0);
        vm.prank(challenger);
        vm.expectRevert(
            abi.encodeWithSelector(ChallengeRegistry.ChallengeWindowZero.selector, auth, CeremonyAxis.Reveal)
        );
        registry.openChallenge(
            auth, CeremonyAxis.Reveal, ChallengeRegistry.ChallengeReason.IntegrityClaim, keccak256("counter"), 0, noProof
        );
    }

    function test_resolverActionsRequirePdaScopedResolver() external {
        _open();
        vm.prank(otherResolver);
        vm.expectRevert(
            abi.encodeWithSelector(ChallengeRegistry.ChallengeResolverUnauthorized.selector, auth, otherResolver)
        );
        registry.confirmNoIntervention(auth, CeremonyAxis.Reveal, keccak256("resolution"));
    }

    function test_confirmNoInterventionByResolverSucceeds() external {
        _open();
        vm.prank(resolver);
        registry.confirmNoIntervention(auth, CeremonyAxis.Reveal, keccak256("resolution"));
        assertEq(
            uint8(registry.challengeStatus(auth, CeremonyAxis.Reveal)),
            uint8(ChallengeRegistry.ChallengeStatus.ConfirmedNoIntervention)
        );
    }

    function test_extendChallengeCapBounded() external {
        _open();
        vm.prank(resolver);
        registry.extendChallenge(auth, CeremonyAxis.Reveal, uint64(block.timestamp + 2 days));

        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(ChallengeRegistry.ChallengeExtensionCapReached.selector, auth, CeremonyAxis.Reveal)
        );
        registry.extendChallenge(auth, CeremonyAxis.Reveal, uint64(block.timestamp + 3 days));
    }

    function test_pauseNewChallengeUsesSeventyTwoHourCap() external {
        uint64 until = uint64(block.timestamp) + PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
        bytes32 scope = registry.NEW_CHALLENGE_SCOPE();
        vm.prank(timelock);
        registry.pause(scope, until, keccak256("pause"));
        (bool active,,) = registry.isPaused(scope);
        assertTrue(active);

        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(IPausableSurface.PauseDurationTooLong.selector, scope, until + 1, until));
        registry.pause(scope, until + 1, keccak256("pause"));
    }

    // ---------------------------------------------------------------------------
    // C2 (CRITICAL): eligibleChallengersRoot merkle allowlist MUST be enforced on the
    // permissionless (eligibleCaller == address(0)) open path. Against the vulnerable
    // code the root was dead storage: ANY address could openChallenge and halt a
    // reveal/shred ceremony. These tests exercise the actual attack path — a
    // non-allowlisted caller opening a challenge — and the legitimate allowlisted path.
    // ---------------------------------------------------------------------------

    /// @dev Builds a 2-leaf merkle tree over {challenger, stranger} using OZ's
    ///      standard leaf hash (keccak256(abi.encodePacked(addr))) and commutative
    ///      node hashing. Returns (root, proofForChallenger).
    function _challengerAllowlist() internal view returns (bytes32 root, bytes32[] memory proof) {
        bytes32 leafChallenger = keccak256(abi.encodePacked(challenger));
        bytes32 leafStranger = keccak256(abi.encodePacked(stranger));
        root = _commutativeHash(leafChallenger, leafStranger);
        proof = new bytes32[](1);
        proof[0] = leafStranger; // sibling needed to rebuild the root from the challenger leaf
    }

    function _commutativeHash(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function test_C2_nonAllowlistedCallerCannotOpenOnPermissionlessRootPath() external {
        (bytes32 root, bytes32[] memory proof) = _challengerAllowlist();
        // eligibleCaller == address(0): the permissionless-but-allowlisted path the root gates.
        _configureWithRoot(auth, uint64(block.timestamp + 1 days), 1 ether, root, address(0), resolver, 1, treasury);

        // The proof belongs to `challenger`; `stranger`'s leaf differs, so the recomputed
        // root will not match → ChallengeProofInvalid. On the vulnerable contract this open
        // succeeded (no proof param, no verification), halting the ceremony.
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(ChallengeRegistry.ChallengeProofInvalid.selector, auth, CeremonyAxis.Reveal, stranger)
        );
        registry.openChallenge{ value: 1 ether }(
            auth,
            CeremonyAxis.Reveal,
            ChallengeRegistry.ChallengeReason.IntegrityClaim,
            keccak256("counter"),
            1 ether,
            proof
        );

        // Confirm no challenge was actually recorded — the ceremony is not halted.
        assertEq(
            uint8(registry.challengeStatus(auth, CeremonyAxis.Reveal)),
            uint8(ChallengeRegistry.ChallengeStatus.None)
        );
    }

    function test_C2_emptyProofRejectedWhenRootSet() external {
        (bytes32 root,) = _challengerAllowlist();
        _configureWithRoot(auth, uint64(block.timestamp + 1 days), 1 ether, root, address(0), resolver, 1, treasury);

        // Even the genuine allowlist member cannot open without a valid proof.
        vm.prank(challenger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChallengeRegistry.ChallengeProofInvalid.selector, auth, CeremonyAxis.Reveal, challenger
            )
        );
        registry.openChallenge{ value: 1 ether }(
            auth,
            CeremonyAxis.Reveal,
            ChallengeRegistry.ChallengeReason.IntegrityClaim,
            keccak256("counter"),
            1 ether,
            noProof
        );
    }

    function test_C2_allowlistedCallerWithValidProofOpens() external {
        (bytes32 root, bytes32[] memory proof) = _challengerAllowlist();
        // Sanity: the proof actually verifies against OZ's library off the same leaf hash.
        assertTrue(MerkleProof.verify(proof, root, keccak256(abi.encodePacked(challenger))));

        _configureWithRoot(auth, uint64(block.timestamp + 1 days), 1 ether, root, address(0), resolver, 1, treasury);

        vm.prank(challenger);
        registry.openChallenge{ value: 1 ether }(
            auth,
            CeremonyAxis.Reveal,
            ChallengeRegistry.ChallengeReason.IntegrityClaim,
            keccak256("counter"),
            1 ether,
            proof
        );

        assertEq(
            uint8(registry.challengeStatus(auth, CeremonyAxis.Reveal)),
            uint8(ChallengeRegistry.ChallengeStatus.Open)
        );
    }

    function test_C2_rootUnsetStillPermissionless() external {
        // No root, no eligibleCaller → fully permissionless by config; any caller opens.
        _configureNoRoot(auth, uint64(block.timestamp + 1 days), 1 ether, address(0), resolver, 1);
        vm.prank(stranger);
        registry.openChallenge{ value: 1 ether }(
            auth,
            CeremonyAxis.Reveal,
            ChallengeRegistry.ChallengeReason.IntegrityClaim,
            keccak256("counter"),
            1 ether,
            noProof
        );
        assertEq(
            uint8(registry.challengeStatus(auth, CeremonyAxis.Reveal)),
            uint8(ChallengeRegistry.ChallengeStatus.Open)
        );
    }

    // ---------------------------------------------------------------------------
    // B3-bond (HIGH): a resolver action (confirmNoIntervention / haltCeremony) used to
    // leave record.bond stranded in the contract forever (no refund, no slash). These
    // tests prove the bond is now refunded to the challenger on ConfirmedNoIntervention
    // and forfeited to the configured treasury on Halted, with record.bond zeroed.
    // ---------------------------------------------------------------------------

    function test_B3_bond_refundedOnConfirmNoIntervention() external {
        _open(); // challenger posts 1 ether bond
        uint256 challengerBefore = challenger.balance;
        uint256 contractBefore = address(registry).balance;
        assertEq(contractBefore, 1 ether, "bond should be escrowed in the contract");

        vm.prank(resolver);
        registry.confirmNoIntervention(auth, CeremonyAxis.Reveal, keccak256("resolution"));

        // Vulnerable code: challenger.balance unchanged, 1 ether stuck in the contract.
        assertEq(challenger.balance, challengerBefore + 1 ether, "challenger must be refunded the bond");
        assertEq(address(registry).balance, 0, "no bond may remain stranded in the contract");
        assertEq(
            registry.challengeConfig(auth, CeremonyAxis.Reveal).requiredBond, 1 ether, "config untouched by resolution"
        );
    }

    function test_B3_bond_forfeitedToTreasuryOnHalt() external {
        _open(); // challenger posts 1 ether bond, treasury is configured
        uint256 treasuryBefore = treasury.balance;

        vm.prank(resolver);
        registry.haltCeremony(auth, CeremonyAxis.Reveal, keccak256("resolution"));

        // Vulnerable code: treasury.balance unchanged, 1 ether stuck in the contract.
        assertEq(treasury.balance, treasuryBefore + 1 ether, "bad-faith bond must be forfeited to treasury");
        assertEq(address(registry).balance, 0, "no bond may remain stranded in the contract");
        assertEq(
            uint8(registry.challengeStatus(auth, CeremonyAxis.Reveal)),
            uint8(ChallengeRegistry.ChallengeStatus.Halted)
        );
    }

    function test_B3_bond_haltWithoutTreasuryReverts() external {
        // Forfeit destination unset + a non-zero bond → refuse to silently strand it.
        _configureWithRoot(
            auth, uint64(block.timestamp + 1 days), 1 ether, bytes32(0), challenger, resolver, 1, address(0)
        );
        vm.prank(challenger);
        registry.openChallenge{ value: 1 ether }(
            auth,
            CeremonyAxis.Reveal,
            ChallengeRegistry.ChallengeReason.IntegrityClaim,
            keccak256("counter"),
            1 ether,
            noProof
        );

        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChallengeRegistry.ChallengeForfeitNoDestination.selector, auth, CeremonyAxis.Reveal
            )
        );
        registry.haltCeremony(auth, CeremonyAxis.Reveal, keccak256("resolution"));

        // Bond is still claimable by the challenger via withdraw because resolution reverted.
        assertEq(address(registry).balance, 1 ether, "bond stays escrowed when forfeit cannot complete");
    }

    function test_B3_bond_doubleResolveCannotDoubleSpend() external {
        _open();
        vm.prank(resolver);
        registry.confirmNoIntervention(auth, CeremonyAxis.Reveal, keccak256("resolution"));

        // Second resolution must revert (status no longer Open) — no second payout.
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(ChallengeRegistry.ChallengeWindowClosed.selector, auth, CeremonyAxis.Reveal)
        );
        registry.confirmNoIntervention(auth, CeremonyAxis.Reveal, keccak256("resolution-2"));
        assertEq(address(registry).balance, 0, "no residual balance after single settlement");
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// @dev Opens a default challenge: eligibleCaller-gated to `challenger`, no merkle root,
    ///      treasury configured, 1 ether bond posted.
    function _open() internal {
        _configureWithRoot(
            auth, uint64(block.timestamp + 1 days), 1 ether, bytes32(0), challenger, resolver, 1, treasury
        );
        vm.prank(challenger);
        registry.openChallenge{ value: 1 ether }(
            auth,
            CeremonyAxis.Reveal,
            ChallengeRegistry.ChallengeReason.IntegrityClaim,
            keccak256("counter"),
            1 ether,
            noProof
        );
    }

    function _configureNoRoot(
        bytes32 authorizationId,
        uint64 windowEnd,
        uint256 bond,
        address eligibleCaller,
        address scopedResolver,
        uint8 maxExtensions
    ) internal {
        _configureWithRoot(
            authorizationId, windowEnd, bond, bytes32(0), eligibleCaller, scopedResolver, maxExtensions, treasury
        );
    }

    function _configureWithRoot(
        bytes32 authorizationId,
        uint64 windowEnd,
        uint256 bond,
        bytes32 eligibleChallengersRoot,
        address eligibleCaller,
        address scopedResolver,
        uint8 maxExtensions,
        address forfeitTreasury
    ) internal {
        vm.prank(orchestrator);
        registry.configureChallenge(
            authorizationId,
            CeremonyAxis.Reveal,
            windowEnd,
            bond,
            eligibleChallengersRoot,
            eligibleCaller,
            scopedResolver,
            maxExtensions,
            forfeitTreasury
        );
    }
}
