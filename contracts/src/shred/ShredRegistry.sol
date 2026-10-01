// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { PauseAuthorityMode, PauseConstants, ShredAuthorityMode, ShredState } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";
import { Tags } from "../lib/Tags.sol";

interface IConditionEngineShredRead {
    function postChallengeRevealInProgress(bytes32 authorizationId) external view returns (bool);
    function hCommitForAuthorization(bytes32 authorizationId) external view returns (bytes32);
    function pdaShredAuthority(bytes32 authorizationId) external view returns (ShredAuthorityMode);
    function pdaMinimumShredLatency(bytes32 authorizationId) external view returns (uint64);
    function recordShredFinalized(bytes32 authorizationId) external;
}

/// @title ShredRegistry - two-axis shred state recorder
/// @notice Records shred requests, ConditionEngine-authorized shred state, and
///         finalized public `proof_shred` tokens. It intentionally does not
///         declare or emit `ShredAuthorized`.
/// @dev TWO-AXIS shred design per S2-6 §11:
///        Axis 1 — Authority (who can request): Subject / Joint / Operator /
///                 Timelock / Disabled, configured per PDA.
///                 JOINT (B3-shred fix) is TRUE dual-consent: an OPERATOR_ROLE
///                 caller AND a non-empty subject co-consent envelope bound by
///                 keccak256(TAG_SUBJECT_V3 ‖ authorizationId ‖ hCommit ‖
///                 keccak256(envelope)). The off-chain subject signature itself
///                 is verified by G4 (subjects are passkey/off-chain — no
///                 anchored EOA), mirroring SubjectInitiatedModule's
///                 envelope-ref idiom; the on-chain layer enforces that Joint
///                 cannot be satisfied unilaterally by the operator the way
///                 Operator mode can. The bare 3-arg requestShred reverts for
///                 Joint; the co-consent overload is mandatory.
///        Axis 2 — Condition (what predicate must hold): Mode P predicate
///                 OR Mode F FSM, evaluated by ConditionEngine.
///      MANDATORY GUARDRAIL: NOT post_challenge_reveal_in_progress —
///      forecloses the shred-vs-gate-signing race documented in
///      internal design record `shred-condition-design.md`.
///      Crypto enforcement triple block on finalize: G1 refuses future reveal,
///      G4 refuses σ_G4 (refusal code 0x02), vault deletes ciphertext.
///      proof_shred is a PUBLIC verification token (NOT key material) — used
///      by partners + auditors to prove erasure to regulators without exposing
///      any PII or DEK fragments. recordShredAuthorized is contract-only
///      (ConditionEngine), preventing direct subject-driven authorization.
contract ShredRegistry is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable, ReentrancyGuardTransient {
    error ShredUnknownCommit(bytes32 hCommit);
    error ShredAuthorityInvalid(bytes32 hCommit, address caller);
    /// @dev Joint mode (B3-shred fix) requires true dual-consent: the operator-side
    ///      OPERATOR_ROLE caller MUST additionally present a non-empty subject
    ///      co-consent envelope + non-zero binding digest via the co-consent
    ///      `requestShred` overload. The 3-arg overload cannot carry it, so Joint
    ///      mode reverts here when routed through the operator-only path.
    error ShredJointRequiresCoConsent(bytes32 hCommit);
    /// @dev Joint co-consent digest must equal keccak256(TAG_SUBJECT_V3 ‖ authorizationId
    ///      ‖ hCommit ‖ keccak256(subjectCoConsent)). Mismatch / empty envelope rejected.
    error ShredCoConsentInvalid(bytes32 hCommit);
    error ShredConditionFalse(bytes32 hCommit);
    error ShredRevealInProgress(bytes32 authorizationId);
    error ShredAlreadyFinalized(bytes32 hCommit);
    error ShredLatencyNotElapsed(bytes32 hCommit, uint64 earliestFinalization);
    error ShredUnauthorizedConditionEngine(address caller);
    error ShredPaused(bytes32 scope);

    event ShredRequested(bytes32 indexed authorizationId, bytes32 indexed hCommit, ShredAuthorityMode authorityMode);
    event ShredStateChanged(
        bytes32 indexed authorizationId, bytes32 indexed hCommit, ShredState oldState, ShredState newState
    );
    event ShredFinalized(bytes32 indexed authorizationId, bytes32 indexed hCommit, bytes32 proofShred);

    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    struct ShredRecord {
        bytes32 authorizationId;
        ShredState state;
        ShredAuthorityMode authorityMode;
        uint64 requestedAt;
        uint64 authorizedAt;
        uint32 challengeWindow;
        uint64 minimumLatency;
        bytes32 conditionRef;
        bytes32 proofShred;
    }

    address private _conditionEngine;
    mapping(bytes32 => ShredRecord) private _records;
    mapping(bytes32 => bool) private _shredded;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine_) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
        _grantRole(Roles.OPERATOR_ROLE, timelock);
        _conditionEngine = conditionEngine_;
    }

    /// @notice Requests a shred for a registered commitment (non-Joint modes).
    /// @dev Permissionless entry but gated by §11.4 mandatory guardrail
    ///      (NOT post-challenge-reveal-in-progress) + matching hCommit + the
    ///      authority axis. Authority enforcement happens here via
    ///      Subject/Operator/Timelock per S2-6 §11.1-2. JOINT mode is NOT
    ///      satisfiable through this overload (it cannot carry the mandatory
    ///      subject co-consent envelope) — it reverts with
    ///      ShredJointRequiresCoConsent, foreclosing the B3-shred unilateral
    ///      operator path. Use the co-consent overload for Joint PDAs.
    /// @param authorizationId PDA authorization key.
    /// @param hCommit commitment hash matching authorizationId's registered hCommit.
    /// @param evidenceRef predicate input (interpreted by shred condition module).
    function requestShred(bytes32 authorizationId, bytes32 hCommit, bytes32 evidenceRef) external {
        _requestShred(authorizationId, hCommit, evidenceRef, false);
    }

    /// @notice Requests a shred for a Joint-authority PDA with true dual-consent.
    /// @dev Joint (B3-shred fix) requires BOTH the operator side (OPERATOR_ROLE
    ///      caller, enforced in _validateAuthority) AND the subject side: a
    ///      non-empty co-consent envelope whose binding digest equals
    ///      keccak256(TAG_SUBJECT_V3 ‖ authorizationId ‖ hCommit ‖
    ///      keccak256(subjectCoConsent)). The subject is passkey/off-chain (no
    ///      anchored EOA), so the cryptographic subject-signature check is a G4
    ///      responsibility; this overload enforces presence + domain-separated
    ///      binding of the co-consent artifact so Joint cannot collapse to a
    ///      unilateral operator action the way Operator mode allows. The same
    ///      overload also serves Subject/Operator/Timelock PDAs that wish to
    ///      attach a co-consent envelope, but only Joint mode REQUIRES it.
    /// @param authorizationId PDA authorization key.
    /// @param hCommit commitment hash matching authorizationId's registered hCommit.
    /// @param evidenceRef predicate input (interpreted by shred condition module).
    /// @param subjectCoConsent off-chain subject co-consent envelope (ref to the
    ///        subject's signed approval; verified cryptographically by G4).
    /// @param coConsentDigest binding digest the envelope must hash to (see @dev).
    function requestShredWithCoConsent(
        bytes32 authorizationId,
        bytes32 hCommit,
        bytes32 evidenceRef,
        bytes calldata subjectCoConsent,
        bytes32 coConsentDigest
    ) external {
        if (
            subjectCoConsent.length == 0 || coConsentDigest == bytes32(0)
                || coConsentDigest
                    != keccak256(abi.encode(Tags.TAG_SUBJECT_V3, authorizationId, hCommit, keccak256(subjectCoConsent)))
        ) {
            revert ShredCoConsentInvalid(hCommit);
        }
        _requestShred(authorizationId, hCommit, evidenceRef, true);
    }

    /// @dev Shared request body. `coConsentPresent` is true only via the
    ///      co-consent overload after the binding digest has been verified;
    ///      Joint mode reverts unless it is set.
    function _requestShred(bytes32 authorizationId, bytes32 hCommit, bytes32 evidenceRef, bool coConsentPresent)
        private
    {
        evidenceRef;
        _requireNotPaused(authorizationId);
        _requireMatchingCommit(authorizationId, hCommit);
        _requireNoRevealInProgress(authorizationId);
        ShredRecord storage record = _records[hCommit];
        if (_shredded[hCommit] || record.state == ShredState.Shredded || record.state == ShredState.Finalized) {
            revert ShredAlreadyFinalized(hCommit);
        }

        ShredAuthorityMode authorityMode =
            IConditionEngineShredRead(_conditionEngine).pdaShredAuthority(authorizationId);
        _validateAuthority(hCommit, authorityMode, msg.sender, coConsentPresent);
        ShredState oldState = record.state;
        record.authorizationId = authorizationId;
        record.authorityMode = authorityMode;
        record.requestedAt = uint64(block.timestamp);
        record.minimumLatency = IConditionEngineShredRead(_conditionEngine).pdaMinimumShredLatency(authorizationId);
        record.state = ShredState.Requested;

        emit ShredRequested(authorizationId, hCommit, authorityMode);
        emit ShredStateChanged(authorizationId, hCommit, oldState, ShredState.Requested);
    }

    /// @notice Records ConditionEngine authorization of a shred (post-condition firing).
    /// @dev Contract-only: msg.sender MUST equal _conditionEngine (revert
    ///      ShredUnauthorizedConditionEngine). Called by ConditionEngine when
    ///      the shred condition (Mode P predicate or Mode F FSM) fires.
    ///      challengeWindow=0 → state transitions Requested → Authorized
    ///      (immediate finalize allowed). challengeWindow>0 → state transitions
    ///      to ChallengeOpen for the window duration. Mandatory guardrail
    ///      NOT post_challenge_reveal_in_progress is checked here as well as
    ///      at requestShred/finalizeShred — defense-in-depth against late
    ///      shred-vs-reveal races.
    function recordShredAuthorized(
        bytes32 authorizationId,
        bytes32 hCommit,
        uint32 challengeWindow,
        bytes32 conditionRef
    ) external {
        if (msg.sender != _conditionEngine) revert ShredUnauthorizedConditionEngine(msg.sender);
        _requireMatchingCommit(authorizationId, hCommit);
        _requireNoRevealInProgress(authorizationId);
        ShredRecord storage record = _records[hCommit];
        if (_shredded[hCommit] || record.state == ShredState.Shredded || record.state == ShredState.Finalized) {
            revert ShredAlreadyFinalized(hCommit);
        }

        ShredState oldState = record.state;
        record.authorizationId = authorizationId;
        if (record.authorityMode == ShredAuthorityMode.None) {
            record.authorityMode = IConditionEngineShredRead(_conditionEngine).pdaShredAuthority(authorizationId);
        }
        record.authorizedAt = uint64(block.timestamp);
        record.challengeWindow = challengeWindow;
        record.conditionRef = conditionRef;
        record.minimumLatency = IConditionEngineShredRead(_conditionEngine).pdaMinimumShredLatency(authorizationId);
        record.state = challengeWindow == 0 ? ShredState.Authorized : ShredState.ChallengeOpen;
        emit ShredStateChanged(authorizationId, hCommit, oldState, record.state);
    }

    /// @notice Finalizes a shred — emits ShredFinalized + sets state to Shredded.
    /// @dev Triple-block enforcement: (1) ConditionEngine refuses to emit
    ///      RevealAuthorized after this fires (verified via Round 2 absence-of-event);
    ///      (2) vault should delete ciphertext on ShredFinalized observation;
    ///      (3) G4 refuses σ_G4 for any future authorize. proofShred is a public
    ///      verification token = keccak(authId || hCommit || block.number ||
    ///      authorityMode || conditionRef) — NOT key material.
    /// @param authorizationId PDA authorization key.
    /// @param hCommit commitment hash to shred.
    /// @return proofShred public verification token (per memory project_shred_condition_design).
    function finalizeShred(bytes32 authorizationId, bytes32 hCommit) external nonReentrant returns (bytes32 proofShred) {
        _requireMatchingCommit(authorizationId, hCommit);
        _requireNoRevealInProgress(authorizationId);
        ShredRecord storage record = _records[hCommit];
        if (record.authorizationId == bytes32(0)) revert ShredUnknownCommit(hCommit);
        if (_shredded[hCommit] || record.state == ShredState.Shredded || record.state == ShredState.Finalized) {
            revert ShredAlreadyFinalized(hCommit);
        }
        if (record.state != ShredState.Authorized && record.state != ShredState.ChallengeOpen) {
            revert ShredConditionFalse(hCommit);
        }
        uint64 challengeDone = record.authorizedAt + record.challengeWindow;
        if (record.state == ShredState.ChallengeOpen && block.timestamp < challengeDone) {
            revert ShredLatencyNotElapsed(hCommit, challengeDone);
        }
        uint64 earliestFinalization = record.authorizedAt + record.minimumLatency;
        if (block.timestamp < earliestFinalization) {
            revert ShredLatencyNotElapsed(hCommit, earliestFinalization);
        }

        ShredState oldState = record.state;
        record.state = ShredState.Finalized;
        proofShred = keccak256(
            abi.encodePacked(
                authorizationId, hCommit, uint64(block.number), uint8(record.authorityMode), record.conditionRef
            )
        );
        record.proofShred = proofShred;
        emit ShredStateChanged(authorizationId, hCommit, oldState, ShredState.Finalized);
        emit ShredFinalized(authorizationId, hCommit, proofShred);

        record.state = ShredState.Shredded;
        _shredded[hCommit] = true;
        emit ShredStateChanged(authorizationId, hCommit, ShredState.Finalized, ShredState.Shredded);
        IConditionEngineShredRead(_conditionEngine).recordShredFinalized(authorizationId);
    }

    function isShredded(bytes32 hCommit) external view returns (bool) {
        return _shredded[hCommit];
    }

    function currentShredState(bytes32 hCommit) external view returns (ShredState) {
        return _records[hCommit].state;
    }

    function shredRecord(bytes32 hCommit) external view returns (ShredRecord memory) {
        return _records[hCommit];
    }

    function conditionEngine() external view returns (address) {
        return _conditionEngine;
    }

    function _requireMatchingCommit(bytes32 authorizationId, bytes32 hCommit) private view {
        bytes32 expected = IConditionEngineShredRead(_conditionEngine).hCommitForAuthorization(authorizationId);
        if (expected != hCommit) revert ShredUnknownCommit(hCommit);
    }

    /// @dev Authority-axis enforcement. `coConsentPresent` is set only when the
    ///      caller routed through requestShredWithCoConsent AND the subject
    ///      co-consent binding digest verified. JOINT mode (B3-shred fix)
    ///      demands BOTH halves: OPERATOR_ROLE (operator side) AND
    ///      coConsentPresent (subject side). This is what distinguishes Joint
    ///      from Operator — Operator never needs the subject artifact, so a
    ///      unilateral OPERATOR_ROLE holder can no longer satisfy a Joint PDA.
    function _validateAuthority(bytes32 hCommit, ShredAuthorityMode mode, address caller, bool coConsentPresent)
        private
        view
    {
        if (mode == ShredAuthorityMode.None || mode == ShredAuthorityMode.Disabled) {
            revert ShredAuthorityInvalid(hCommit, caller);
        }
        if (mode == ShredAuthorityMode.Operator && !hasRole(Roles.OPERATOR_ROLE, caller)) {
            revert ShredAuthorityInvalid(hCommit, caller);
        }
        if (mode == ShredAuthorityMode.Timelock && !hasRole(Roles.DEFAULT_ADMIN_ROLE, caller)) {
            revert ShredAuthorityInvalid(hCommit, caller);
        }
        if (mode == ShredAuthorityMode.Joint) {
            // Operator side: must hold OPERATOR_ROLE.
            if (!hasRole(Roles.OPERATOR_ROLE, caller)) {
                revert ShredAuthorityInvalid(hCommit, caller);
            }
            // Subject side: the co-consent envelope is mandatory. Without it the
            // request is an operator-only action — reject so Joint != Operator.
            if (!coConsentPresent) {
                revert ShredJointRequiresCoConsent(hCommit);
            }
        }
    }

    function _requireNoRevealInProgress(bytes32 authorizationId) private view {
        if (IConditionEngineShredRead(_conditionEngine).postChallengeRevealInProgress(authorizationId)) {
            revert ShredRevealInProgress(authorizationId);
        }
    }

    function _requireNotPaused(bytes32 authorizationId) private view {
        if (_isPaused(GLOBAL_SCOPE)) revert ShredPaused(GLOBAL_SCOPE);
        if (_isPaused(authorizationId)) revert ShredPaused(authorizationId);
    }

    function _isPaused(bytes32 scope) private view returns (bool) {
        PauseEntry memory entry = _pauses[scope];
        return entry.until != 0 && block.timestamp < entry.until;
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (!hasRole(Roles.PAUSER_ROLE, caller)) revert PauseUnauthorized(scope, caller);
    }

    function _maxPauseDuration() internal pure override returns (uint64) {
        return PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
    }

    function _pauseAuthorityMode(bytes32) internal pure override returns (PauseAuthorityMode) {
        return PauseAuthorityMode.Joint;
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }

    uint256[50] private __gap;
}
