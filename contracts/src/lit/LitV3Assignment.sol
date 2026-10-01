// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

/// @title LitV3Assignment - on-chain mirror of Lit V3 TEE operator assignments
/// @notice Records which Lit V3 operator-instance is assigned to sign σ_Lit
///         for each authorizationId. Lit V3 is one of the 4 gates in the V3
///         AND-composition; its σ contribution is required for any reveal.
///         This contract is the on-chain bridge-output: the Lit Network's
///         governance decides assignments, and a privileged bridge writes
///         those decisions here so combiners can verify which TEE produced
///         which σ_Lit at commit_block.
/// @dev One-shot recording per authorizationId (recordAssignment reverts
///      LitAssignmentExists on second call). Amendments use recordCorrection,
///      which appends a NEW history entry without overwriting the prior one
///      (append-only audit trail). getAssignment returns the LATEST entry;
///      getAssignmentAt + assignmentHistoryLength expose the full history.
///      LIT_GOVERNANCE_BRIDGE_ROLE is the sole writer — this role is held
///      by the Lit-Network → on-chain bridge per S2-3 §6.1.
contract LitV3Assignment is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable {
    struct AssignmentRecord {
        bytes32 assignedTeeId;
        uint64 assignmentBlock;
        bytes assignedTeePubkey;
        bytes32 sourceGovernanceDigest;
        bool correction;
    }

    error LitAssignmentExists(bytes32 authorizationId);
    error LitAssignmentMissing(bytes32 authorizationId);
    error LitUnauthorizedBridge(address caller);
    error LitAssignmentPaused(bytes32 scope);

    event LitAssignmentRecorded(
        bytes32 indexed authorizationId,
        bytes32 indexed assignedTeeId,
        uint64 assignmentBlock,
        bytes32 sourceGovernanceDigest
    );

    event LitAssignmentCorrectionRecorded(
        bytes32 indexed authorizationId,
        bytes32 indexed assignedTeeId,
        uint64 assignmentBlock,
        bytes32 sourceGovernanceDigest
    );

    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;
    bytes32 public constant PAUSER_ROLE = Roles.PAUSER_ROLE;
    bytes32 public constant LIT_GOVERNANCE_BRIDGE_ROLE = Roles.LIT_GOVERNANCE_BRIDGE_ROLE;
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    mapping(bytes32 => AssignmentRecord[]) private _recordsByAuthorization;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
    }

    /// @notice Records the Lit V3 TEE operator assignment for an authorization.
    /// @dev LIT_GOVERNANCE_BRIDGE_ROLE only (`_requireBridge`). One-shot per
    ///      authorizationId — re-recording reverts LitAssignmentExists. Use
    ///      recordCorrection for legitimate amendments. Bridge writes mirror
    ///      governance decisions from the Lit Network for per-commit assignment.
    /// @param authorizationId target PDA authorization.
    /// @param assignedTeeId Lit V3 operator-instance identifier.
    /// @param assignmentBlock block at which Lit governance assigned this operator.
    /// @param assignedTeePubkey ephemeral pubkey for per-commit DCAP attestation.
    /// @param sourceGovernanceDigest hash of the Lit governance source decision.
    function recordAssignment(
        bytes32 authorizationId,
        bytes32 assignedTeeId,
        uint64 assignmentBlock,
        bytes calldata assignedTeePubkey,
        bytes32 sourceGovernanceDigest
    ) external {
        _requireBridge();
        _requireNotPaused(GLOBAL_SCOPE);
        if (_recordsByAuthorization[authorizationId].length != 0) {
            revert LitAssignmentExists(authorizationId);
        }
        _append(authorizationId, assignedTeeId, assignmentBlock, assignedTeePubkey, sourceGovernanceDigest, false);
        emit LitAssignmentRecorded(authorizationId, assignedTeeId, assignmentBlock, sourceGovernanceDigest);
    }

    /// @notice Records a correction to a previously-recorded assignment.
    /// @dev LIT_GOVERNANCE_BRIDGE_ROLE only, pause-respecting. Appends a
    ///      NEW entry with correction=true rather than mutating prior
    ///      entries — full audit history is preserved. Reverts
    ///      LitAssignmentMissing if no prior assignment exists for this
    ///      authorizationId (use recordAssignment for the first entry).
    ///      getAssignment will return this NEW entry; consumers needing
    ///      historical state use getAssignmentAt with an explicit index.
    function recordCorrection(
        bytes32 authorizationId,
        bytes32 assignedTeeId,
        uint64 assignmentBlock,
        bytes calldata assignedTeePubkey,
        bytes32 sourceGovernanceDigest
    ) external {
        _requireBridge();
        _requireNotPaused(GLOBAL_SCOPE);
        if (_recordsByAuthorization[authorizationId].length == 0) {
            revert LitAssignmentMissing(authorizationId);
        }
        _append(authorizationId, assignedTeeId, assignmentBlock, assignedTeePubkey, sourceGovernanceDigest, true);
        emit LitAssignmentCorrectionRecorded(authorizationId, assignedTeeId, assignmentBlock, sourceGovernanceDigest);
    }

    /// @notice Returns the LATEST assignment record (including any correction).
    /// @dev View. Reverts LitAssignmentMissing if no records exist.
    ///      Combiners use this to verify that the σ_Lit contributor at reveal
    ///      time matches the Lit governance-assigned TEE at commit_block.
    ///      For historical lookup or correction-aware reasoning, see
    ///      getAssignmentAt + assignmentHistoryLength.
    function getAssignment(bytes32 authorizationId)
        external
        view
        returns (
            bytes32 assignedTeeId,
            uint64 assignmentBlock,
            bytes memory assignedTeePubkey,
            bytes32 sourceGovernanceDigest
        )
    {
        AssignmentRecord[] storage records = _recordsByAuthorization[authorizationId];
        if (records.length == 0) {
            revert LitAssignmentMissing(authorizationId);
        }
        AssignmentRecord storage record = records[records.length - 1];
        return (record.assignedTeeId, record.assignmentBlock, record.assignedTeePubkey, record.sourceGovernanceDigest);
    }

    function assignmentHistoryLength(bytes32 authorizationId) external view returns (uint256) {
        return _recordsByAuthorization[authorizationId].length;
    }

    function getAssignmentAt(bytes32 authorizationId, uint256 index) external view returns (AssignmentRecord memory) {
        AssignmentRecord[] storage records = _recordsByAuthorization[authorizationId];
        if (index >= records.length) {
            revert LitAssignmentMissing(authorizationId);
        }
        return records[index];
    }

    function _append(
        bytes32 authorizationId,
        bytes32 assignedTeeId,
        uint64 assignmentBlock,
        bytes calldata assignedTeePubkey,
        bytes32 sourceGovernanceDigest,
        bool correction
    ) internal {
        _recordsByAuthorization[authorizationId].push(
            AssignmentRecord({
                assignedTeeId: assignedTeeId,
                assignmentBlock: assignmentBlock,
                assignedTeePubkey: assignedTeePubkey,
                sourceGovernanceDigest: sourceGovernanceDigest,
                correction: correction
            })
        );
    }

    function _requireBridge() internal view {
        if (!hasRole(Roles.LIT_GOVERNANCE_BRIDGE_ROLE, msg.sender)) {
            revert LitUnauthorizedBridge(msg.sender);
        }
    }

    function _requireNotPaused(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert LitAssignmentPaused(scope);
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
