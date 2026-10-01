// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Test } from "forge-std/Test.sol";

import { EmergencyGovernance } from "../../src/governance/EmergencyGovernance.sol";
import { CealisSecurityMultisig } from "../../src/governance/CealisSecurityMultisig.sol";
import { CealisTimelockController } from "../../src/governance/CealisTimelockController.sol";
import { Roles } from "../../src/lib/Roles.sol";

contract EmergencyGovernanceTest is Test {
    CealisTimelockController internal timelock;
    CealisSecurityMultisig internal security;
    EmergencyGovernance internal emergency;

    address internal emergencySigner = address(0xEAA);
    address internal stranger = address(0xBEEF);
    address internal deployerAdmin = address(this);

    function setUp() public {
        vm.warp(1_000_000);

        address[] memory empty = new address[](0);
        timelock = new CealisTimelockController(7 days, empty, empty, address(this));

        security = CealisSecurityMultisig(
            address(
                new ERC1967Proxy(
                    address(new CealisSecurityMultisig()),
                    abi.encodeCall(
                        CealisSecurityMultisig.initialize, (address(this), address(timelock), address(1), empty)
                    )
                )
            )
        );

        address[] memory signers = new address[](1);
        signers[0] = emergencySigner;
        emergency = EmergencyGovernance(
            address(
                new ERC1967Proxy(
                    address(new EmergencyGovernance()),
                    abi.encodeCall(
                        EmergencyGovernance.initialize, (address(this), address(security), address(timelock), signers)
                    )
                )
            )
        );
        security.setEmergencyGovernance(address(emergency));
    }

    /// @notice SC-F-05: UPGRADER_ROLE must be held by the timelock, never by the
    ///         deployer-admin, at init time. Against the vulnerable code (which granted
    ///         UPGRADER to `admin`), the deployer-admin held UPGRADER and could upgrade
    ///         the proxy in the window before PostDeploy transferred control — this test
    ///         asserts that window does not exist.
    function test_SC_F_05_upgraderRoleIsTimelockOnlyNotDeployerAdmin() external {
        // The timelock — and only the timelock — holds UPGRADER_ROLE from block one.
        assertTrue(emergency.hasRole(Roles.UPGRADER_ROLE, address(timelock)));
        // The deployer-admin (DEFAULT_ADMIN_ROLE for wiring) must NOT hold UPGRADER_ROLE.
        assertFalse(emergency.hasRole(Roles.UPGRADER_ROLE, deployerAdmin));
        // The deployer-admin still has DEFAULT_ADMIN for deploy-time wiring.
        assertTrue(emergency.hasRole(Roles.DEFAULT_ADMIN_ROLE, deployerAdmin));
        // The stored timelock pointer matches what was passed at init.
        assertEq(emergency.timelockController(), address(timelock));
    }

    /// @notice SC-F-05 attack path: the deployer-admin cannot UUPS-upgrade the proxy
    ///         to a malicious impl before control transfer, because UPGRADER_ROLE is
    ///         not theirs. Against the vulnerable code this upgrade would have
    ///         succeeded (admin held UPGRADER).
    function test_SC_F_05_deployerAdminCannotUpgrade() external {
        address newImpl = address(new EmergencyGovernance());
        vm.prank(deployerAdmin);
        vm.expectRevert();
        emergency.upgradeToAndCall(newImpl, "");
    }

    /// @notice SC-F-05: zero timelock address is rejected at init.
    function test_SC_F_05_zeroTimelockReverts() external {
        address[] memory signers = new address[](0);
        EmergencyGovernance impl = new EmergencyGovernance();
        vm.expectRevert(EmergencyGovernance.EmergencyGovernanceZeroAddress.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(EmergencyGovernance.initialize, (address(this), address(security), address(0), signers))
        );
    }

    function test_suspendSecurityCouncilWithinBoundAccepted() external {
        uint64 until = uint64(block.timestamp + 7 days);

        vm.prank(emergencySigner);
        emergency.suspendSecurityCouncil(until, keccak256("incident"));

        assertEq(emergency.suspendedUntil(), until);
        assertEq(security.suspendedUntil(), until);
    }

    function test_suspendSecurityCouncilTooLongReverts() external {
        uint64 until = uint64(block.timestamp + 7 days + 1);
        uint64 maxAllowed = uint64(block.timestamp + 7 days);

        vm.prank(emergencySigner);
        vm.expectRevert(
            abi.encodeWithSelector(EmergencyGovernance.EmergencySuspensionTooLong.selector, until, maxAllowed)
        );
        emergency.suspendSecurityCouncil(until, keccak256("too-long"));
    }

    function test_restoreSecurityCouncilClearsSuspension() external {
        vm.prank(emergencySigner);
        emergency.suspendSecurityCouncil(uint64(block.timestamp + 1 days), keccak256("incident"));

        vm.prank(emergencySigner);
        emergency.restoreSecurityCouncil(keccak256("restored"));

        assertEq(emergency.suspendedUntil(), 0);
        assertEq(security.suspendedUntil(), 0);
    }

    function test_unauthorizedCallerReverts() external {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(EmergencyGovernance.EmergencyGovernanceUnauthorized.selector, stranger));
        emergency.suspendSecurityCouncil(uint64(block.timestamp + 1 days), keccak256("incident"));
    }
}
