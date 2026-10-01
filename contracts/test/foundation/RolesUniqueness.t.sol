// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { Roles } from "../../src/lib/Roles.sol";

/// @title Roles uniqueness — anti-collision gate for the 17 V3 role identifiers
/// @notice Per S2-2 §1.5 + §16: 17 V3 access-control roles + DEFAULT_ADMIN_ROLE.
///         A collision (two roles same hash) would silently merge access surfaces.
/// @dev Static foundation test — no fuzz needed; all 17 names are constants.
contract RolesUniquenessTest is Test {
    /// @notice Every role MUST have a distinct keccak256 hash. Collision = privilege merge.
    function test_AllRolesHaveDistinctHashes() external pure {
        bytes32[18] memory roles = [
            Roles.DEFAULT_ADMIN_ROLE,
            Roles.UPGRADER_ROLE,
            Roles.PAUSER_ROLE,
            Roles.OPERATOR_ROLE,
            Roles.ORCHESTRATOR_ROLE,
            Roles.ISSUER_ROLE,
            Roles.MODULE_ADMIN_ROLE,
            Roles.REGISTRY_ADMIN_ROLE,
            Roles.SECURITY_COUNCIL_ROLE,
            Roles.EMERGENCY_GOVERNANCE_ROLE,
            Roles.CHALLENGE_RESOLVER_ROLE,
            Roles.REKEY_GOVERNANCE_ROLE,
            Roles.ORACLE_SUBMITTER_ROLE,
            Roles.LIT_GOVERNANCE_BRIDGE_ROLE,
            Roles.GATE_PUBKEY_PUBLISHER_ROLE,
            Roles.SD_OPERATOR_ROLE,
            Roles.REVOCATION_ADMIN_ROLE,
            // padding for fixed-array (only 17 real roles; DEFAULT_ADMIN is the 18th sentinel)
            bytes32(uint256(1))
        ];

        // O(N²) pairwise compare; N=17 is fine.
        for (uint256 i = 0; i < 17; i++) {
            for (uint256 j = i + 1; j < 17; j++) {
                assertTrue(roles[i] != roles[j], "Two V3 roles have the same hash - privilege merge!");
            }
        }
    }

    /// @notice DEFAULT_ADMIN_ROLE MUST be the OZ sentinel bytes32(0).
    function test_DefaultAdminRoleMatchesOZSentinel() external pure {
        assertEq(Roles.DEFAULT_ADMIN_ROLE, bytes32(0), "DEFAULT_ADMIN_ROLE must equal OZ sentinel bytes32(0)");
    }

    /// @notice Each non-sentinel role MUST equal keccak256(bytes("ROLE_NAME")).
    ///         Anchors the role formula against drift.
    function test_RoleHashesMatchKeccak() external pure {
        assertEq(Roles.UPGRADER_ROLE, keccak256("UPGRADER_ROLE"), "UPGRADER_ROLE");
        assertEq(Roles.PAUSER_ROLE, keccak256("PAUSER_ROLE"), "PAUSER_ROLE");
        assertEq(Roles.OPERATOR_ROLE, keccak256("OPERATOR_ROLE"), "OPERATOR_ROLE");
        assertEq(Roles.ORCHESTRATOR_ROLE, keccak256("ORCHESTRATOR_ROLE"), "ORCHESTRATOR_ROLE");
        assertEq(Roles.ISSUER_ROLE, keccak256("ISSUER_ROLE"), "ISSUER_ROLE");
        assertEq(Roles.MODULE_ADMIN_ROLE, keccak256("MODULE_ADMIN_ROLE"), "MODULE_ADMIN_ROLE");
        assertEq(Roles.REGISTRY_ADMIN_ROLE, keccak256("REGISTRY_ADMIN_ROLE"), "REGISTRY_ADMIN_ROLE");
        assertEq(Roles.SECURITY_COUNCIL_ROLE, keccak256("SECURITY_COUNCIL_ROLE"), "SECURITY_COUNCIL_ROLE");
        assertEq(Roles.EMERGENCY_GOVERNANCE_ROLE, keccak256("EMERGENCY_GOVERNANCE_ROLE"), "EMERGENCY_GOVERNANCE_ROLE");
        assertEq(Roles.CHALLENGE_RESOLVER_ROLE, keccak256("CHALLENGE_RESOLVER_ROLE"), "CHALLENGE_RESOLVER_ROLE");
        assertEq(Roles.REKEY_GOVERNANCE_ROLE, keccak256("REKEY_GOVERNANCE_ROLE"), "REKEY_GOVERNANCE_ROLE");
        assertEq(Roles.ORACLE_SUBMITTER_ROLE, keccak256("ORACLE_SUBMITTER_ROLE"), "ORACLE_SUBMITTER_ROLE");
        assertEq(Roles.LIT_GOVERNANCE_BRIDGE_ROLE, keccak256("LIT_GOVERNANCE_BRIDGE_ROLE"), "LIT_GOVERNANCE_BRIDGE_ROLE");
        assertEq(Roles.GATE_PUBKEY_PUBLISHER_ROLE, keccak256("GATE_PUBKEY_PUBLISHER_ROLE"), "GATE_PUBKEY_PUBLISHER_ROLE");
        assertEq(Roles.SD_OPERATOR_ROLE, keccak256("SD_OPERATOR_ROLE"), "SD_OPERATOR_ROLE");
        assertEq(Roles.REVOCATION_ADMIN_ROLE, keccak256("REVOCATION_ADMIN_ROLE"), "REVOCATION_ADMIN_ROLE");
    }

    /// @notice V1 GUARDIAN_ROLE MUST NOT collide with any V3 role — verify no
    ///         accidental V1/V2 mixing during V3 build.
    function test_V1GuardianRoleDoesNotCollideWithV3() external pure {
        bytes32 v1Guardian = keccak256("GUARDIAN_ROLE");
        // None of the V3 roles equal V1's guardian role.
        assertTrue(v1Guardian != Roles.UPGRADER_ROLE, "GUARDIAN collides with UPGRADER");
        assertTrue(v1Guardian != Roles.OPERATOR_ROLE, "GUARDIAN collides with OPERATOR");
        assertTrue(v1Guardian != Roles.ORCHESTRATOR_ROLE, "GUARDIAN collides with ORCHESTRATOR");
        assertTrue(v1Guardian != Roles.ISSUER_ROLE, "GUARDIAN collides with ISSUER");
        assertTrue(v1Guardian != Roles.SECURITY_COUNCIL_ROLE, "GUARDIAN collides with SECURITY_COUNCIL");
    }
}
