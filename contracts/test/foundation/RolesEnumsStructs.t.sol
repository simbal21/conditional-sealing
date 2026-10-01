// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { Roles } from "../../src/lib/Roles.sol";
import {
    CeremonyAxis,
    ConditionalRecipientMode,
    ConditionMode,
    G3Choice,
    G4Phase,
    GateKind,
    LifecycleState,
    PauseAuthorityMode,
    PauseConstants,
    ProtocolVersion,
    ShredAuthorityMode,
    ShredState
} from "../../src/lib/Enums.sol";

/// @title RolesEnumsStructs.t - sanity gate for foundation symbol values
contract RolesEnumsStructsTest is Test {
    // ---------------------------------------------------------------------
    // Roles - 17 V3 role identifiers
    // ---------------------------------------------------------------------

    function test_Roles_DefaultAdminMatchesOZ() external pure {
        assertEq(Roles.DEFAULT_ADMIN_ROLE, bytes32(0), "OZ AccessControl admin sentinel == 0x00");
    }

    function test_Roles_CriticalKeccakValuesPinned() external pure {
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
        assertEq(
            Roles.LIT_GOVERNANCE_BRIDGE_ROLE, keccak256("LIT_GOVERNANCE_BRIDGE_ROLE"), "LIT_GOVERNANCE_BRIDGE_ROLE"
        );
        assertEq(
            Roles.GATE_PUBKEY_PUBLISHER_ROLE, keccak256("GATE_PUBKEY_PUBLISHER_ROLE"), "GATE_PUBKEY_PUBLISHER_ROLE"
        );
        assertEq(Roles.SD_OPERATOR_ROLE, keccak256("SD_OPERATOR_ROLE"), "SD_OPERATOR_ROLE");
        assertEq(Roles.REVOCATION_ADMIN_ROLE, keccak256("REVOCATION_ADMIN_ROLE"), "REVOCATION_ADMIN_ROLE");
    }

    function test_Roles_AllRolesUnique() external pure {
        bytes32[17] memory roles = [
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
            Roles.REVOCATION_ADMIN_ROLE
        ];
        for (uint256 i = 0; i < roles.length; i++) {
            for (uint256 j = i + 1; j < roles.length; j++) {
                assertTrue(roles[i] != roles[j], "duplicate role identifier");
            }
        }
    }

    // ---------------------------------------------------------------------
    // LifecycleState - 10 states verbatim from S2-2 App. A
    // ---------------------------------------------------------------------

    function test_LifecycleState_TenStatesVerbatim() external pure {
        assertEq(uint256(LifecycleState.Unregistered), 0);
        assertEq(uint256(LifecycleState.Registered), 1);
        assertEq(uint256(LifecycleState.RevealConditionMet), 2);
        assertEq(uint256(LifecycleState.RevealChallengeOpen), 3);
        assertEq(uint256(LifecycleState.PostChallengeRevealInProgress), 4);
        assertEq(uint256(LifecycleState.RevealCompleted), 5);
        assertEq(uint256(LifecycleState.ShredConditionMet), 6);
        assertEq(uint256(LifecycleState.ShredChallengeOpen), 7);
        assertEq(uint256(LifecycleState.Shredded), 8);
        assertEq(uint256(LifecycleState.Paused), 9);
    }

    // ---------------------------------------------------------------------
    // PauseAuthorityMode - exactly 3 values, no shred-axis spillover
    // ---------------------------------------------------------------------

    function test_PauseAuthorityMode_ExactlyThreeValues_PartnerJointNone() external pure {
        assertEq(uint256(PauseAuthorityMode.Partner), 0);
        assertEq(uint256(PauseAuthorityMode.Joint), 1);
        assertEq(uint256(PauseAuthorityMode.None), 2);
        // Type cast above value 2 would revert at runtime - we trust the enum decl.
    }

    // ---------------------------------------------------------------------
    // ShredAuthorityMode - 6 values, None == 0 invalid sentinel
    // ---------------------------------------------------------------------

    function test_ShredAuthorityMode_NoneIsInvalidSentinelAtIndexZero() external pure {
        assertEq(uint256(ShredAuthorityMode.None), 0, "invalid sentinel at 0");
        assertEq(uint256(ShredAuthorityMode.Subject), 1);
        assertEq(uint256(ShredAuthorityMode.Joint), 2);
        assertEq(uint256(ShredAuthorityMode.Operator), 3);
        assertEq(uint256(ShredAuthorityMode.Timelock), 4);
        assertEq(uint256(ShredAuthorityMode.Disabled), 5);
    }

    // ---------------------------------------------------------------------
    // ConditionalRecipientMode - Mode 3 reserved
    // ---------------------------------------------------------------------

    function test_ConditionalRecipientMode_Mode3Reserved() external pure {
        assertEq(uint256(ConditionalRecipientMode.None), 0);
        assertEq(uint256(ConditionalRecipientMode.PasskeyAccount), 1);
        assertEq(uint256(ConditionalRecipientMode.WalletEOA), 2);
        assertEq(uint256(ConditionalRecipientMode.WalletEIP1271Reserved), 3, "Mode 3 == 3");
    }

    // ---------------------------------------------------------------------
    // ConditionMode / G4Phase / G3Choice / GateKind / CeremonyAxis / ShredState
    // ---------------------------------------------------------------------

    function test_ConditionMode_NoneSentinel_ModeFOne_ModePTwo() external pure {
        assertEq(uint256(ConditionMode.None), 0);
        assertEq(uint256(ConditionMode.ModeF), 1);
        assertEq(uint256(ConditionMode.ModeP), 2);
    }

    function test_G4Phase_NoneSentinel_Phase1Phase2() external pure {
        assertEq(uint256(G4Phase.None), 0);
        assertEq(uint256(G4Phase.Phase1), 1);
        assertEq(uint256(G4Phase.Phase2), 2);
    }

    function test_G3Choice_DcipherZero_DrandOne() external pure {
        assertEq(uint256(G3Choice.Dcipher), 0);
        assertEq(uint256(G3Choice.Drand), 1);
    }

    function test_GateKind_FiveKinds() external pure {
        assertEq(uint256(GateKind.LitV3), 0);
        assertEq(uint256(GateKind.Dcipher), 1);
        assertEq(uint256(GateKind.Drand), 2);
        assertEq(uint256(GateKind.G4), 3);
        assertEq(uint256(GateKind.ConditionalRecipient), 4);
    }

    function test_CeremonyAxis_RevealZero_ShredOne() external pure {
        assertEq(uint256(CeremonyAxis.Reveal), 0);
        assertEq(uint256(CeremonyAxis.Shred), 1);
    }

    function test_ShredState_SevenValuesIncludingNone() external pure {
        assertEq(uint256(ShredState.None), 0);
        assertEq(uint256(ShredState.Requested), 1);
        assertEq(uint256(ShredState.Authorized), 2);
        assertEq(uint256(ShredState.Finalized), 3);
        assertEq(uint256(ShredState.Blocked), 4);
        assertEq(uint256(ShredState.ChallengeOpen), 5);
        assertEq(uint256(ShredState.Shredded), 6);
    }

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    function test_Constants_BuildProtocolVersionIs0x0302() external pure {
        assertEq(ProtocolVersion.BUILD_PROTOCOL_VERSION, 0x0302);
    }

    function test_Constants_PauseDurations() external pure {
        assertEq(PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS, 259_200, "72 hours");
        assertEq(PauseConstants.MAX_REGISTRY_PAUSE_SECONDS, 604_800, "7 days");
        assertEq(PauseConstants.MAX_EMERGENCY_PAUSE_SECONDS, 604_800, "7 days");
    }
}
