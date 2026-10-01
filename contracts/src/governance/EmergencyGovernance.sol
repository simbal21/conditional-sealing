// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

interface ISecurityCouncilSuspender {
    function suspendSecurityCouncil(uint64 until, bytes32 reasonRef) external;
    function restoreSecurityCouncil(bytes32 reasonRef) external;
}

/// @title EmergencyGovernance
/// @notice Bounded circuit breaker that can suspend the security council's
///         registry-deprecation authority for at most seven days.
contract EmergencyGovernance is Initializable, AccessControl, UUPSUpgradeable {
    error EmergencyGovernanceUnauthorized(address caller);
    error EmergencySuspensionTooLong(uint64 requested, uint64 maxAllowed);
    error EmergencyGovernanceZeroAddress();

    event SecurityCouncilSuspended(uint64 until, bytes32 reasonRef);
    event SecurityCouncilRestored(bytes32 reasonRef);

    bytes32 public constant EMERGENCY_GOVERNANCE_ROLE = Roles.EMERGENCY_GOVERNANCE_ROLE;
    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;

    address public securityMultisig;
    uint64 public suspendedUntil;
    // SC-F-05: appended after existing storage (append-only for upgradeable layout).
    address public timelockController;

    /// @dev SC-F-05: UPGRADER_ROLE is granted to `timelockController_`, never to
    ///      `admin`. Mirrors CealisSecurityMultisig.initialize. The deploy flow seats
    ///      a temporary deployer-admin for wiring, then PostDeploy hands DEFAULT_ADMIN
    ///      to the timelock; binding UPGRADER to the timelock at init forecloses the
    ///      pre-transfer window in which the deployer could UUPS-upgrade the proxy.
    ///      `timelockController_` is appended to the signature (was absent before this
    ///      fix); the Deploy/_deployEmergency call-site must pass the timelock address.
    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address securityMultisig_,
        address timelockController_,
        address[] calldata signers
    ) external initializer {
        if (admin == address(0) || securityMultisig_ == address(0) || timelockController_ == address(0)) {
            revert EmergencyGovernanceZeroAddress();
        }
        securityMultisig = securityMultisig_;
        timelockController = timelockController_;
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, admin);
        _grantRole(Roles.UPGRADER_ROLE, timelockController_);
        for (uint256 i = 0; i < signers.length; ++i) {
            if (signers[i] == address(0)) revert EmergencyGovernanceZeroAddress();
            _grantRole(Roles.EMERGENCY_GOVERNANCE_ROLE, signers[i]);
        }
    }

    /// @notice Sets the Security Multisig contract address that this Emergency
    ///         governance is paired with.
    /// @dev DEFAULT_ADMIN_ROLE only. Reverts on zero. Used at construction + if
    ///      Security Multisig is rotated. Pairs with the §10A.4 distinct-multisig
    ///      invariant (Emergency may suspend Security; the two MUST be different
    ///      Safe instances).
    function setSecurityMultisig(address securityMultisig_) external onlyRole(Roles.DEFAULT_ADMIN_ROLE) {
        if (securityMultisig_ == address(0)) revert EmergencyGovernanceZeroAddress();
        securityMultisig = securityMultisig_;
    }

    /// @notice Suspends the Security Council's deprecation authority until `until`.
    /// @dev EMERGENCY_GOVERNANCE_ROLE only. Cap = block.timestamp +
    ///      PauseConstants.MAX_EMERGENCY_PAUSE_SECONDS (~90 days). Cascades into
    ///      ISecurityCouncilSuspender(securityMultisig).suspendSecurityCouncil
    ///      which flips the corresponding flag on the Security Multisig. Use case:
    ///      Emergency Governance detects malicious Security Multisig action and
    ///      freezes their deprecation authority pending review.
    /// @param until UTC timestamp until which Security Council is suspended.
    /// @param reasonRef opaque reference for off-chain reason documentation.
    function suspendSecurityCouncil(uint64 until, bytes32 reasonRef) external {
        if (!hasRole(Roles.EMERGENCY_GOVERNANCE_ROLE, msg.sender)) {
            revert EmergencyGovernanceUnauthorized(msg.sender);
        }
        uint64 maxAllowed = uint64(block.timestamp + PauseConstants.MAX_EMERGENCY_PAUSE_SECONDS);
        if (until > maxAllowed) revert EmergencySuspensionTooLong(until, maxAllowed);
        suspendedUntil = until;
        ISecurityCouncilSuspender(securityMultisig).suspendSecurityCouncil(until, reasonRef);
        emit SecurityCouncilSuspended(until, reasonRef);
    }

    /// @notice Restores the Security Council's deprecation authority immediately.
    /// @dev EMERGENCY_GOVERNANCE_ROLE only. Reverse of suspendSecurityCouncil.
    /// @param reasonRef opaque reference for off-chain reason documentation.
    function restoreSecurityCouncil(bytes32 reasonRef) external {
        if (!hasRole(Roles.EMERGENCY_GOVERNANCE_ROLE, msg.sender)) {
            revert EmergencyGovernanceUnauthorized(msg.sender);
        }
        suspendedUntil = 0;
        ISecurityCouncilSuspender(securityMultisig).restoreSecurityCouncil(reasonRef);
        emit SecurityCouncilRestored(reasonRef);
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }

    uint256[50] private __gap;
}
