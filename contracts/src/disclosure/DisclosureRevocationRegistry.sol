// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

/// @title DisclosureRevocationRegistry - SD disclosure revocation tracking
/// @notice Tracks revocation state of SD (Selective Disclosure) outputs delivered
///         at onboarding time. Once revoked, downstream partners verifying the
///         disclosure must reject it as no-longer-valid. This is the on-chain
///         half of the SD revocation flow per S2-7 §11.
/// @dev Two-step lifecycle: registerDisclosure (ORCHESTRATOR_ROLE, exactly-once)
///      → revokeDisclosure (REVOCATION_ADMIN_ROLE OR per-record authorizedRevoker,
///      one-shot). The authorizedRevoker is captured at register-time and gives
///      a permissionless-at-signature-level path while still gating effective
///      callers to a pre-authorized address (subject device, partner, or
///      Cealis itself depending on PDA policy). Privacy default per S2-7
///      App. I §I.11: subject_commitment_v3 is NEVER emitted in events;
///      only disclosureId + authorizationId are indexed.
contract DisclosureRevocationRegistry is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable {
    error DisclosureUnknown(bytes32 disclosureId);
    error DisclosureAlreadyRevoked(bytes32 disclosureId);
    error DisclosureAlreadyRegistered(bytes32 disclosureId);
    error DisclosureRevocationUnauthorized(bytes32 disclosureId);
    error DisclosureRevocationPaused(bytes32 scope);

    event DisclosureRegistered(
        bytes32 indexed disclosureId,
        bytes32 indexed authorizationId,
        bytes32 indexed claimId,
        bytes32 verifierRef,
        uint64 expiryTimestamp,
        address authorizedRevoker
    );
    event DisclosureRevoked(
        bytes32 indexed disclosureId, bytes32 indexed authorizationId, uint8 reasonCode, bytes32 evidenceRef
    );

    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;
    bytes32 public constant PAUSER_ROLE = Roles.PAUSER_ROLE;
    bytes32 public constant ORCHESTRATOR_ROLE = Roles.ORCHESTRATOR_ROLE;
    bytes32 public constant REVOCATION_ADMIN_ROLE = Roles.REVOCATION_ADMIN_ROLE;
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    struct DisclosureRecord {
        bool registered;
        bool revoked;
        bytes32 authorizationId;
        bytes32 claimId;
        bytes32 verifierRef;
        uint64 expiryTimestamp;
        address authorizedRevoker;
    }

    mapping(bytes32 => DisclosureRecord) private _records;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
    }

    /// @notice Registers an SD disclosure for revocation tracking.
    /// @dev ORCHESTRATOR_ROLE only, pause-respecting. Single-shot per
    ///      disclosureId — DisclosureAlreadyRegistered prevents replay
    ///      registrations under the same id. authorizedRevoker_ captured
    ///      at register-time enables a per-disclosure delegation: the
    ///      subject, partner, or any pre-arranged address can revoke
    ///      without holding global REVOCATION_ADMIN_ROLE. expiryTimestamp_
    ///      is informational (off-chain verifiers SHOULD treat post-expiry
    ///      disclosures as expired regardless of revocation state).
    function registerDisclosure(
        bytes32 disclosureId,
        bytes32 authorizationId,
        bytes32 claimId,
        bytes32 verifierRef,
        uint64 expiryTimestamp_,
        address authorizedRevoker_
    ) external onlyRole(Roles.ORCHESTRATOR_ROLE) {
        _requireNotPaused(GLOBAL_SCOPE);
        if (_records[disclosureId].registered) {
            revert DisclosureAlreadyRegistered(disclosureId);
        }
        _records[disclosureId] = DisclosureRecord({
            registered: true,
            revoked: false,
            authorizationId: authorizationId,
            claimId: claimId,
            verifierRef: verifierRef,
            expiryTimestamp: expiryTimestamp_,
            authorizedRevoker: authorizedRevoker_
        });
        emit DisclosureRegistered(
            disclosureId, authorizationId, claimId, verifierRef, expiryTimestamp_, authorizedRevoker_
        );
    }

    /// @notice Revokes a previously-registered SD disclosure (one-shot per disclosureId).
    /// @dev Access control is INTERNAL via hasRole(REVOCATION_ADMIN_ROLE) OR
    ///      msg.sender == record.authorizedRevoker (set at registerDisclosure
    ///      ORCHESTRATOR-gated time). Permissionless at the signature level but
    ///      gated by per-record `authorizedRevoker` OR global REVOCATION_ADMIN.
    ///      Emits DisclosureRevoked indexing disclosureId + authorizationId only —
    ///      subject_commitment_v3 deliberately NOT emitted per S2-7 App. I §I.11
    ///      privacy-default.
    /// @param disclosureId target SD disclosure key.
    /// @param reasonCode revocation reason (6 codes per S2-7 §11.5).
    /// @param evidenceRef optional revocation-evidence hash for off-chain audit trail.
    function revokeDisclosure(bytes32 disclosureId, uint8 reasonCode, bytes32 evidenceRef) external {
        _requireNotPaused(GLOBAL_SCOPE);
        DisclosureRecord storage record = _records[disclosureId];
        if (!record.registered) {
            revert DisclosureUnknown(disclosureId);
        }
        if (record.revoked) {
            revert DisclosureAlreadyRevoked(disclosureId);
        }
        if (!hasRole(Roles.REVOCATION_ADMIN_ROLE, msg.sender) && msg.sender != record.authorizedRevoker) {
            revert DisclosureRevocationUnauthorized(disclosureId);
        }
        record.revoked = true;
        emit DisclosureRevoked(disclosureId, record.authorizationId, reasonCode, evidenceRef);
    }

    /// @notice Returns whether a disclosure has been revoked.
    /// @dev View. Reverts DisclosureUnknown if disclosureId was never registered.
    ///      Pause-respecting via _requireNotPausedView — if the registry is
    ///      paused, callers cannot rely on revocation state (verifiers should
    ///      treat this as "halt verification" not "permit disclosure").
    function isRevoked(bytes32 disclosureId) external view returns (bool) {
        _requireNotPausedView(GLOBAL_SCOPE);
        DisclosureRecord storage record = _records[disclosureId];
        if (!record.registered) {
            revert DisclosureUnknown(disclosureId);
        }
        return record.revoked;
    }

    function authorizedRevoker(bytes32 disclosureId) external view returns (address) {
        DisclosureRecord storage record = _records[disclosureId];
        if (!record.registered) {
            revert DisclosureUnknown(disclosureId);
        }
        return record.authorizedRevoker;
    }

    function expiryTimestamp(bytes32 disclosureId) external view returns (uint64) {
        DisclosureRecord storage record = _records[disclosureId];
        if (!record.registered) {
            revert DisclosureUnknown(disclosureId);
        }
        return record.expiryTimestamp;
    }

    function _requireNotPaused(bytes32 scope) internal view {
        _requireNotPausedView(scope);
    }

    function _requireNotPausedView(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert DisclosureRevocationPaused(scope);
        }
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (!hasRole(Roles.PAUSER_ROLE, caller)) {
            revert PauseUnauthorized(scope, caller);
        }
    }

    function _maxPauseDuration() internal pure override returns (uint64) {
        return PauseConstants.MAX_REGISTRY_PAUSE_SECONDS;
    }

    function _pauseAuthorityMode(bytes32) internal pure override returns (PauseAuthorityMode) {
        return PauseAuthorityMode.Joint;
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }

    uint256[50] private __gap;
}
