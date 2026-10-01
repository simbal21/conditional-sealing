// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { AttestationGate } from "../../src/attestation/AttestationGate.sol";
import { IAttestationGate } from "../../src/engine/IConditionEngine.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract AttestationGateFuzzTest is Test {
    AttestationGate internal gate;
    address internal timelock = address(0xA11CE);
    address internal mockOracleRegistry = address(0x10001);
    address internal mockSchemaRegistry = address(0x10002);
    address internal mockDslRegistry = address(0x10003);
    address internal mockClaimDsl = address(0x10004);

    function setUp() public {
        gate = AttestationGate(
            ProxyDeploy.deployProxy(
                address(new AttestationGate()),
                abi.encodeCall(
                    AttestationGate.initialize,
                    (timelock, mockOracleRegistry, mockSchemaRegistry, mockDslRegistry, mockClaimDsl)
                )
            )
        );
        vm.warp(1_000_000);
    }

    /// @notice σ-as-AUTHORIZATION hostile-bytes guard MUST reject 96-byte signatures
    /// regardless of any other input — defense-in-depth per dek-lifecycle.md.
    function testFuzz_verifyOracleAttestation_RejectsSigmaShapedBytes(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes32 claimRef,
        bytes32 sigPart1,
        bytes32 sigPart2,
        bytes32 sigPart3
    ) external {
        // Construct exactly 96 bytes — the canonical sigma length
        bytes memory sigmaShaped = abi.encodePacked(sigPart1, sigPart2, sigPart3);
        assertEq(sigmaShaped.length, 96, "test invariant: sigmaShaped must be 96 bytes");

        vm.expectRevert(IAttestationGate.AttestationSigmaBytesForbidden.selector);
        gate.verifyOracleAttestation(authorizationId, oracleId, schemaId, attestationDigest, sigmaShaped, claimRef);
    }

    /// @notice Operator-only setters reject non-OPERATOR callers for any args.
    function testFuzz_setAuthorizationBlock_UnauthorizedRevert(
        address caller,
        bytes32 authorizationId,
        uint64 pinnedBlock
    ) external {
        vm.assume(caller != address(0));
        vm.assume(caller != timelock); // timelock has OPERATOR_ROLE at init
        vm.prank(caller);
        vm.expectRevert(); // AccessControl rejects
        gate.setAuthorizationBlock(authorizationId, pinnedBlock);
    }

    /// @notice setClaimDSLVersion permissionless gate — non-OPERATOR rejected.
    function testFuzz_setClaimDSLVersion_UnauthorizedRevert(
        address caller,
        bytes32 claimRef,
        bytes32 dslVersionRef
    ) external {
        vm.assume(caller != address(0));
        vm.assume(caller != timelock);
        vm.prank(caller);
        vm.expectRevert();
        gate.setClaimDSLVersion(claimRef, dslVersionRef);
    }

    /// @notice OPERATOR can set authorization block to ANY uint64 value.
    function testFuzz_setAuthorizationBlock_AcceptsAnyArgs(bytes32 authorizationId, uint64 pinnedBlock) external {
        vm.prank(timelock);
        gate.setAuthorizationBlock(authorizationId, pinnedBlock);
        assertEq(gate.authorizationBlock(authorizationId), pinnedBlock, "pin round-trip");
    }

    /// @notice setMaxAttestationAgeSeconds only by OPERATOR — non-operator rejected.
    function testFuzz_setMaxAttestationAgeSeconds_UnauthorizedRevert(address caller, uint64 maxAge) external {
        vm.assume(caller != address(0));
        vm.assume(caller != timelock);
        vm.prank(caller);
        vm.expectRevert();
        gate.setMaxAttestationAgeSeconds(maxAge);
    }
}
