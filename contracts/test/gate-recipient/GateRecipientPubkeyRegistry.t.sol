// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { GateRecipientPubkeyRegistry } from "../../src/gate-recipient/GateRecipientPubkeyRegistry.sol";
import { GateKind, PauseConstants } from "../../src/lib/Enums.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { IPausableSurface } from "../../src/base/IPausableSurface.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract GateRecipientPubkeyRegistryTest is Test {
    GateRecipientPubkeyRegistry internal registry;

    address internal timelock = address(0x1001);
    address internal publisher = address(0x1002);

    bytes32 internal auth = keccak256("auth");
    bytes32 internal attestationRef = keccak256("attestation");

    function setUp() public {
        vm.warp(1_000_000);
        registry = GateRecipientPubkeyRegistry(
            ProxyDeploy.deployProxy(
                address(new GateRecipientPubkeyRegistry()),
                abi.encodeCall(GateRecipientPubkeyRegistry.initialize, (timelock))
            )
        );
        vm.prank(timelock);
        registry.grantRole(Roles.GATE_PUBKEY_PUBLISHER_ROLE, publisher);
    }

    function test_getPubkeyAt_UsesFourParamSignature() external {
        vm.prank(publisher);
        registry.publishPubkey(_entry(uint8(GateKind.LitV3), true, 0, 0));

        GateRecipientPubkeyRegistry.GateRecipientPubkeyEntry memory got =
            registry.getPubkeyAt(auth, uint8(GateKind.LitV3), 0, uint64(block.number));

        assertEq(got.authorizationId, auth);
        assertEq(got.gateKind, uint8(GateKind.LitV3));
        assertEq(got.conditionalRecipientIndex, 0);
        assertEq(got.kemPubkey, hex"010203");
    }

    function test_perCommitEphemeralPublisherSucceeds() external {
        vm.expectEmit(true, true, true, true);
        emit GateRecipientPubkeyRegistry.GateRecipientPubkeyPublished(auth, uint8(GateKind.G4), 0, attestationRef);
        vm.prank(publisher);
        registry.publishPubkey(_entry(uint8(GateKind.G4), true, 0, 0));

        assertEq(registry.historyLength(auth, uint8(GateKind.G4), 0), 1);
    }

    function test_drandLongLivedWithoutTimelockRoleReverts() external {
        vm.prank(publisher);
        vm.expectRevert(
            abi.encodeWithSelector(
                GateRecipientPubkeyRegistry.GatePubkeyTimelockRequired.selector, uint8(GateKind.Drand)
            )
        );
        registry.publishPubkey(_entry(uint8(GateKind.Drand), false, 0, 0));
    }

    function test_drandLongLivedThroughRegistryAdminSucceedsAfterDelay() external {
        vm.roll(block.number + 42);
        vm.prank(timelock);
        registry.publishPubkey(_entry(uint8(GateKind.Drand), false, uint64(block.number), 0));

        GateRecipientPubkeyRegistry.GateRecipientPubkeyEntry memory got =
            registry.getPubkeyAt(auth, uint8(GateKind.Drand), 0, uint64(block.number));
        assertFalse(got.perCommitEphemeral);
    }

    function test_historicalLookupHonorsTombstoneBlock() external {
        uint64 effective = uint64(block.number);
        uint64 tombstone = effective + 5;
        vm.prank(publisher);
        registry.publishPubkey(_entry(uint8(GateKind.LitV3), true, effective, tombstone));

        GateRecipientPubkeyRegistry.GateRecipientPubkeyEntry memory got =
            registry.getPubkeyAt(auth, uint8(GateKind.LitV3), 0, tombstone - 1);
        assertEq(got.tombstoneBlock, tombstone);

        vm.expectRevert(
            abi.encodeWithSelector(
                GateRecipientPubkeyRegistry.GatePubkeyUnknown.selector, auth, uint8(GateKind.LitV3), uint16(0)
            )
        );
        registry.getPubkeyAt(auth, uint8(GateKind.LitV3), 0, tombstone);
    }

    function test_pauseUsesSevenDayRegistryCap() external {
        uint64 until = uint64(block.timestamp) + PauseConstants.MAX_REGISTRY_PAUSE_SECONDS;
        vm.prank(timelock);
        registry.pause(bytes32(0), until, keccak256("reason"));
        (bool active,,) = registry.isPaused(bytes32(0));
        assertTrue(active);

        vm.prank(timelock);
        vm.expectRevert(
            abi.encodeWithSelector(IPausableSurface.PauseDurationTooLong.selector, bytes32(0), until + 1, until)
        );
        registry.pause(bytes32(0), until + 1, keccak256("reason"));
    }

    /// F-6: a privileged publisher cannot backdate effectiveBlock to a PAST block (which would
    /// let the entry shadow the legitimate as-of-commit key for an already-committed
    /// authorization via getPubkeyAt's reverse scan). Reject < block.number; allow == and >.
    function test_F_6_backdatedEffectiveBlockRejected() external {
        vm.roll(block.number + 100);
        uint64 nowBlock = uint64(block.number);
        uint64 pastBlock = nowBlock - 10;

        // Backdated publish must revert.
        vm.prank(publisher);
        vm.expectRevert(
            abi.encodeWithSelector(
                GateRecipientPubkeyRegistry.GatePubkeyEffectiveBlockBackdated.selector, pastBlock, nowBlock
            )
        );
        registry.publishPubkey(_entry(uint8(GateKind.LitV3), true, pastBlock, 0));
        assertEq(registry.historyLength(auth, uint8(GateKind.LitV3), 0), 0);

        // Current block (== now) is allowed.
        vm.prank(publisher);
        registry.publishPubkey(_entry(uint8(GateKind.LitV3), true, nowBlock, 0));
        assertEq(registry.historyLength(auth, uint8(GateKind.LitV3), 0), 1);

        // Forward-dated (scheduled rotation, > now) is allowed.
        vm.prank(publisher);
        registry.publishPubkey(_entry(uint8(GateKind.LitV3), true, nowBlock + 50, 0));
        assertEq(registry.historyLength(auth, uint8(GateKind.LitV3), 0), 2);
    }

    function _entry(uint8 gateKind, bool perCommit, uint64 effective, uint64 tombstone)
        internal
        view
        returns (GateRecipientPubkeyRegistry.GateRecipientPubkeyEntry memory)
    {
        return GateRecipientPubkeyRegistry.GateRecipientPubkeyEntry({
            authorizationId: auth,
            gateKind: gateKind,
            conditionalRecipientIndex: 0,
            kemPubkey: hex"010203",
            attestationRef: attestationRef,
            effectiveBlock: effective,
            tombstoneBlock: tombstone,
            perCommitEphemeral: perCommit
        });
    }
}
