// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { Roles } from "../lib/Roles.sol";

interface ICealisGovernedRegistry {
    function deprecateEntry(bytes32 id, uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash) external;
    function queueCanonicalDeprecation(
        bytes32 id,
        uint8 reasonCode,
        bytes32 disclosureCid,
        bytes32 disclosureCommitHash
    ) external;
    function executeCanonicalDeprecation(bytes32 id) external;
}

interface ICealisExpeditedTimelock {
    function scheduleExpeditedOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external returns (bytes32 operationId);
}

/// @title CealisSecurityMultisig
/// @notice Phase-1-compatible security-council contract surface for instant
///         non-canonical deprecation and expedited canonical deprecation.
/// @dev Phase 1 seats may all be Cealis-controlled. The role/API shape is
///      still the Phase 2 surface so external advisor seats can be added
///      without changing registry ABIs.
contract CealisSecurityMultisig is Initializable, AccessControl, UUPSUpgradeable {
    error SecurityMultisigUnauthorized(address caller);
    error SecurityMultisigCanonicalDelayRequired(bytes32 registryId, bytes32 entryId);
    error SecurityMultisigSuspended(uint64 until);
    error SecurityMultisigRegistryUnknown(bytes32 registryId);
    error SecurityMultisigEmergencyUnauthorized(address caller);
    error SecurityMultisigZeroAddress();

    event SecurityDeprecationRequested(bytes32 indexed registryId, bytes32 indexed entryId, uint8 reasonCode);
    event SecurityAuthoritySuspended(uint64 until, bytes32 reasonRef);
    event RegistryMapped(bytes32 indexed registryId, address indexed registry);

    bytes32 public constant SECURITY_COUNCIL_ROLE = Roles.SECURITY_COUNCIL_ROLE;
    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;

    address public timelockController;
    address public emergencyGovernance;
    uint64 public suspendedUntil;
    bytes32 public suspensionReasonRef;
    bytes32 public lastQueuedOperationId;

    mapping(bytes32 => address) private _registries;

    /// @dev SC-F-05: UPGRADER_ROLE is granted to `timelockController_`, never to
    ///      `admin`. The deploy flow seats a temporary deployer-admin so it can wire
    ///      registries/emergency-governance before PostDeploy hands DEFAULT_ADMIN to
    ///      the timelock (see script/PostDeploy.s.sol::_transferUUPSControl). Binding
    ///      UPGRADER to the timelock at init forecloses the pre-transfer window where
    ///      the deployer could otherwise UUPS-upgrade the proxy: at no point does a
    ///      non-timelock holder ever hold UPGRADER_ROLE. _authorizeUpgrade is gated on
    ///      UPGRADER_ROLE, so the upgrade authority is timelock-only from block one.
    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address timelockController_,
        address emergencyGovernance_,
        address[] calldata signers
    ) external initializer {
        if (admin == address(0) || timelockController_ == address(0)) {
            revert SecurityMultisigZeroAddress();
        }
        timelockController = timelockController_;
        emergencyGovernance = emergencyGovernance_;

        _grantRole(Roles.DEFAULT_ADMIN_ROLE, admin);
        _grantRole(Roles.UPGRADER_ROLE, timelockController_);
        for (uint256 i = 0; i < signers.length; ++i) {
            if (signers[i] == address(0)) revert SecurityMultisigZeroAddress();
            _grantRole(Roles.SECURITY_COUNCIL_ROLE, signers[i]);
        }
    }

    /// @notice Maps a logical registryId to the deployed registry contract address.
    /// @dev Access: DEFAULT_ADMIN_ROLE (timelock). Required before the multisig can
    ///      route deprecation calls to a registry. Bi-arg non-zero invariant
    ///      (revert SecurityMultisigZeroAddress). Setting can also be used to
    ///      re-point if a registry is migrated to a new UUPS impl (the impl-level
    ///      upgrade still goes through that registry's own UPGRADER_ROLE).
    function setRegistry(bytes32 registryId, address registry) external onlyRole(Roles.DEFAULT_ADMIN_ROLE) {
        if (registryId == bytes32(0) || registry == address(0)) revert SecurityMultisigZeroAddress();
        _registries[registryId] = registry;
        emit RegistryMapped(registryId, registry);
    }

    function setEmergencyGovernance(address emergencyGovernance_) external onlyRole(Roles.DEFAULT_ADMIN_ROLE) {
        if (emergencyGovernance_ == address(0)) revert SecurityMultisigZeroAddress();
        emergencyGovernance = emergencyGovernance_;
    }

    function registryFor(bytes32 registryId) external view returns (address) {
        return _registry(registryId);
    }

    /// @notice Called BY EmergencyGovernance to freeze this multisig's deprecation
    ///         authority until `until`.
    /// @dev Contract-only: caller MUST equal `emergencyGovernance` (set at construction +
    ///      mutable by DEFAULT_ADMIN_ROLE via setEmergencyGovernance). Pairs with
    ///      EmergencyGovernance.suspendSecurityCouncil — they are the two halves of
    ///      the §10A.4 distinct-multisig pattern.
    function suspendSecurityCouncil(uint64 until, bytes32 reasonRef) external {
        if (msg.sender != emergencyGovernance) revert SecurityMultisigEmergencyUnauthorized(msg.sender);
        suspendedUntil = until;
        suspensionReasonRef = reasonRef;
        emit SecurityAuthoritySuspended(until, reasonRef);
    }

    /// @notice Called BY EmergencyGovernance to immediately restore this multisig's
    ///         deprecation authority.
    /// @dev Contract-only: caller MUST equal `emergencyGovernance`. Reverse of
    ///      suspendSecurityCouncil.
    function restoreSecurityCouncil(bytes32 reasonRef) external {
        if (msg.sender != emergencyGovernance) revert SecurityMultisigEmergencyUnauthorized(msg.sender);
        suspendedUntil = 0;
        suspensionReasonRef = reasonRef;
        emit SecurityAuthoritySuspended(0, reasonRef);
    }

    /// @notice Deprecates a NON-canonical registry entry (no timelock delay).
    /// @dev Access: SECURITY_COUNCIL_ROLE AND not-currently-suspended via
    ///      `_requireCouncil`. Designed for immediate-takedown of compromised
    ///      non-canonical entries (e.g., a deprecated plugin binary an
    ///      attacker has compromised post-add). Cannot deprecate canonical
    ///      entries through this path — those require requestCanonicalDeprecation
    ///      (24h queued via expedited timelock). Calls into registry's
    ///      deprecateEntry which enforces the canonical/non-canonical gate.
    function deprecateNonCanonical(
        bytes32 registryId,
        bytes32 entryId,
        uint8 reasonCode,
        bytes32 disclosureCid,
        bytes32 disclosureCommitHash
    ) external {
        _requireCouncil();
        ICealisGovernedRegistry(_registry(registryId))
            .deprecateEntry(entryId, reasonCode, disclosureCid, disclosureCommitHash);
        emit SecurityDeprecationRequested(registryId, entryId, reasonCode);
    }

    /// @notice Requests deprecation of a CANONICAL registry entry (24h expedited timelock).
    /// @dev Access: SECURITY_COUNCIL_ROLE AND not-suspended. Two-step flow:
    ///      (1) calls registry.queueCanonicalDeprecation to record the
    ///      pending deprecation on-chain, (2) schedules an expedited timelock
    ///      operation that will call registry.executeCanonicalDeprecation
    ///      after the 24h delay. lastQueuedOperationId is stored for visibility.
    ///      Salt incorporates chainId for replay-resistance across forks. The
    ///      24h delay gives downstream consumers time to react to a canonical
    ///      retirement (re-key, plugin swap, oracle migration, etc.).
    function requestCanonicalDeprecation(
        bytes32 registryId,
        bytes32 entryId,
        uint8 reasonCode,
        bytes32 disclosureCid,
        bytes32 disclosureCommitHash
    ) external {
        _requireCouncil();
        address registry = _registry(registryId);
        ICealisGovernedRegistry(registry)
            .queueCanonicalDeprecation(entryId, reasonCode, disclosureCid, disclosureCommitHash);

        bytes memory data = abi.encodeCall(ICealisGovernedRegistry.executeCanonicalDeprecation, (entryId));
        bytes32 salt =
            keccak256(abi.encode(registryId, entryId, reasonCode, disclosureCid, disclosureCommitHash, block.chainid));
        lastQueuedOperationId = ICealisExpeditedTimelock(timelockController)
            .scheduleExpeditedOperation(registry, 0, data, bytes32(0), salt);
        emit SecurityDeprecationRequested(registryId, entryId, reasonCode);
    }

    function _registry(bytes32 registryId) private view returns (address registry) {
        registry = _registries[registryId];
        if (registry == address(0)) revert SecurityMultisigRegistryUnknown(registryId);
    }

    function _requireCouncil() private view {
        if (!hasRole(Roles.SECURITY_COUNCIL_ROLE, msg.sender)) revert SecurityMultisigUnauthorized(msg.sender);
        if (suspendedUntil != 0 && block.timestamp < suspendedUntil) revert SecurityMultisigSuspended(suspendedUntil);
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }

    uint256[50] private __gap;
}
