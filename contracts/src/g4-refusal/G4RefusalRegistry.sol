// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

/// @title G4RefusalRegistry - G4 refusal + advisory signal registry (10-code taxonomy)
/// @notice Records G4's decisions to refuse signing σ_G4 for a given commit, plus
///         advisory (non-blocking) signals. The crypto-non-custody invariant
///         hinges on this: when G4 refuses, no σ_G4 → no Shamir reconstruction
///         → no DEK → no reveal. G4 cannot be coerced to sign because there is
///         no path that bypasses the refusal — the chain enforces "if registered
///         refusal, then no reveal" via on-chain checks at finalize time.
/// @dev 10-code taxonomy (S2-2 §14.2):
///        Per-commit blocking (0x01-0x05):
///          0x01 LEGAL_COMPEL   - court-ordered hold on a specific commit
///          0x02 ART_17_ERASURE - GDPR erasure request (encrypted-reason only)
///          0x03 ART_18_RESTRICTION - GDPR processing-restriction (encrypted)
///          0x04 INTEGRITY_FAIL - on-chain integrity mismatch
///          0x05 CHAIN_MISMATCH - chain-state diverged from commit expectations
///        Class-wide blocking (0x06-0x09):
///          0x06 PLUGIN_DEPRECATED    - canonical age-plugin retracted
///          0x07 AUTHORITY_DEPRECATED - canonical G4 authority retired
///          0x08 DSL_DEPRECATED       - canonical Claim DSL retired
///          0x09 ORACLE_DEPRECATED    - canonical oracle retired
///        Advisory non-blocking (0x0A):
///          0x0A OPT_OUT_ACTIVE - subject opted out of class-wide halt
///      0x02/0x03 MUST use refuseEncrypted (privacy: erasure/restriction
///      reasons are subject-PII). refusePublic rejects them.
contract G4RefusalRegistry is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable {
    error RefusalUnknown(bytes32 authorizationId);
    error RefusalInvalidReason(uint8 reasonCode);
    error RefusalSensitiveReasonMustBeEncrypted(uint8 reasonCode);
    error RefusalAdvisoryReasonNotBlocking(uint8 reasonCode);
    error RefusalBlockingReasonRequired(uint8 reasonCode);
    error RefusalPaused(bytes32 scope);

    event RefusalSignal(bytes32 indexed authorizationId, bytes32 indexed hCommit, uint8 reasonCode, bool blocking);
    event RefusalReasonPublic(bytes32 indexed authorizationId, uint8 reasonCode, bytes32 proofRef);
    event RefusalReasonEncrypted(bytes32 indexed authorizationId, bytes encryptedReasonBlob);
    event AdvisorySignal(bytes32 indexed authorizationId, bytes32 indexed hCommit, uint8 reasonCode);

    uint8 public constant REASON_LEGAL_COMPEL = 0x01;
    uint8 public constant REASON_ART_17_ERASURE = 0x02;
    uint8 public constant REASON_ART_18_RESTRICTION = 0x03;
    uint8 public constant REASON_INTEGRITY_FAIL = 0x04;
    uint8 public constant REASON_CHAIN_MISMATCH = 0x05;
    uint8 public constant REASON_PLUGIN_DEPRECATED = 0x06;
    uint8 public constant REASON_AUTHORITY_DEPRECATED = 0x07;
    uint8 public constant REASON_DSL_DEPRECATED = 0x08;
    uint8 public constant REASON_ORACLE_DEPRECATED = 0x09;
    uint8 public constant REASON_OPT_OUT_ACTIVE = 0x0A;

    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;
    bytes32 public constant PAUSER_ROLE = Roles.PAUSER_ROLE;
    bytes32 public constant OPERATOR_ROLE = Roles.OPERATOR_ROLE;
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    struct RefusalRecord {
        bool refused;
        uint8 reasonCode;
        bool encrypted;
    }

    struct SignalRecord {
        bool signaled;
        uint8 reasonCode;
    }

    mapping(bytes32 => RefusalRecord) private _refusals;
    mapping(bytes32 => SignalRecord) private _signals;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
    }

    /// @notice Records a G4 signal (refusal or advisory) for an authorization.
    /// @dev OPERATOR-gated (via _requireOperator). 10-code class split per
    ///      S2-2 §14.2: blocking=true requires reason 0x01..0x09; blocking=false
    ///      requires reason 0x0A (opt_out_active advisory). reasonData reserved
    ///      for encrypted-reason payload (0x02/0x03 should use refuseEncrypted
    ///      separate entrypoint).
    /// @param authorizationId target PDA authorization.
    /// @param hCommit commitment hash for cross-reference.
    /// @param reasonCode 0x01..0x0A per G4 refusal-code enum.
    /// @param blocking true → per-commit or class-wide block; false → advisory.
    /// @param reasonData reserved (currently ignored — encrypted-reason mode uses refuseEncrypted).
    function recordSignal(
        bytes32 authorizationId,
        bytes32 hCommit,
        uint8 reasonCode,
        bool blocking,
        bytes calldata reasonData
    ) external {
        reasonData;
        _requireOperator();
        _requireNotPaused(GLOBAL_SCOPE);
        if (blocking) {
            _validateBlockingReason(reasonCode);
            _refusals[authorizationId] = RefusalRecord({ refused: true, reasonCode: reasonCode, encrypted: false });
            _signals[authorizationId] = SignalRecord({ signaled: true, reasonCode: reasonCode });
            emit RefusalSignal(authorizationId, hCommit, reasonCode, true);
        } else {
            _validateAdvisoryReason(reasonCode);
            _signals[authorizationId] = SignalRecord({ signaled: true, reasonCode: reasonCode });
            emit AdvisorySignal(authorizationId, hCommit, reasonCode);
        }
    }

    /// @notice Records a public-reason refusal (non-PII reason codes).
    /// @dev OPERATOR_ROLE-gated, pause-respecting. Accepts blocking reasons
    ///      0x01, 0x04..0x09 — explicitly REJECTS 0x02 (ART_17_ERASURE) and
    ///      0x03 (ART_18_RESTRICTION) per privacy invariant (those MUST go
    ///      through refuseEncrypted). proofRef is an immutable reference
    ///      (e.g., IPFS CID) to the off-chain supporting evidence.
    function refusePublic(bytes32 authorizationId, bytes32 hCommit, uint8 reasonCode, bytes32 proofRef) external {
        _requireOperator();
        _requireNotPaused(GLOBAL_SCOPE);
        _validateBlockingReason(reasonCode);
        if (reasonCode == REASON_ART_17_ERASURE || reasonCode == REASON_ART_18_RESTRICTION) {
            revert RefusalSensitiveReasonMustBeEncrypted(reasonCode);
        }
        _refusals[authorizationId] = RefusalRecord({ refused: true, reasonCode: reasonCode, encrypted: false });
        _signals[authorizationId] = SignalRecord({ signaled: true, reasonCode: reasonCode });
        emit RefusalSignal(authorizationId, hCommit, reasonCode, true);
        emit RefusalReasonPublic(authorizationId, reasonCode, proofRef);
    }

    /// @notice Records an encrypted-reason refusal (PII-bearing reason codes).
    /// @dev OPERATOR_ROLE-gated, pause-respecting. Use for ANY blocking reason
    ///      whose reason payload contains subject PII (most notably 0x02
    ///      ART_17_ERASURE and 0x03 ART_18_RESTRICTION). encryptedReasonBlob
    ///      is the ciphertext only — decryption keys live off-chain with the
    ///      authorized recipient (subject + counsel). On-chain observers see
    ///      "refused with code N, encrypted reason" but cannot read the reason.
    ///      This is how Cealis stays GDPR-compliant while making refusal verifiable.
    function refuseEncrypted(
        bytes32 authorizationId,
        bytes32 hCommit,
        uint8 reasonCode,
        bytes calldata encryptedReasonBlob
    ) external {
        _requireOperator();
        _requireNotPaused(GLOBAL_SCOPE);
        _validateBlockingReason(reasonCode);
        _refusals[authorizationId] = RefusalRecord({ refused: true, reasonCode: reasonCode, encrypted: true });
        _signals[authorizationId] = SignalRecord({ signaled: true, reasonCode: reasonCode });
        emit RefusalSignal(authorizationId, hCommit, reasonCode, true);
        emit RefusalReasonEncrypted(authorizationId, encryptedReasonBlob);
    }

    function recordAdvisorySignal(bytes32 authorizationId, bytes32 hCommit, uint8 reasonCode) external {
        _requireOperator();
        _requireNotPaused(GLOBAL_SCOPE);
        _validateAdvisoryReason(reasonCode);
        _signals[authorizationId] = SignalRecord({ signaled: true, reasonCode: reasonCode });
        emit AdvisorySignal(authorizationId, hCommit, reasonCode);
    }

    function refusalState(bytes32 authorizationId)
        external
        view
        returns (bool refused, uint8 reasonCode, bool encrypted)
    {
        RefusalRecord memory record = _refusals[authorizationId];
        if (!record.refused && !_signals[authorizationId].signaled) {
            revert RefusalUnknown(authorizationId);
        }
        return (record.refused, record.reasonCode, record.encrypted);
    }

    function signalState(bytes32 authorizationId) external view returns (bool signaled, uint8 reasonCode) {
        SignalRecord memory record = _signals[authorizationId];
        if (!record.signaled) {
            revert RefusalUnknown(authorizationId);
        }
        return (record.signaled, record.reasonCode);
    }

    function _validateBlockingReason(uint8 reasonCode) internal pure {
        if (reasonCode == REASON_OPT_OUT_ACTIVE) {
            revert RefusalAdvisoryReasonNotBlocking(reasonCode);
        }
        if (reasonCode < REASON_LEGAL_COMPEL || reasonCode > REASON_ORACLE_DEPRECATED) {
            revert RefusalInvalidReason(reasonCode);
        }
    }

    function _validateAdvisoryReason(uint8 reasonCode) internal pure {
        if (reasonCode != REASON_OPT_OUT_ACTIVE) {
            if (reasonCode >= REASON_LEGAL_COMPEL && reasonCode <= REASON_ORACLE_DEPRECATED) {
                revert RefusalBlockingReasonRequired(reasonCode);
            }
            revert RefusalInvalidReason(reasonCode);
        }
    }

    function _requireOperator() internal view {
        if (!hasRole(Roles.OPERATOR_ROLE, msg.sender)) {
            revert AccessControlUnauthorizedAccount(msg.sender, Roles.OPERATOR_ROLE);
        }
    }

    function _requireNotPaused(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert RefusalPaused(scope);
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
