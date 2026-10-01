// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { CeremonyAxis } from "../lib/Enums.sol";
import { ISubjectInitiatedModule } from "../engine/IConditionEngine.sol";
import { ConditionModuleBase } from "./PaymentObligationModule.sol";

/// @dev SC-F-06: each subject action carries an EIP-712 typed-data signature
///      (`CealisSubjectInitiated` domain, S2-2 §1.6 / §15.1) rather than an opaque
///      envelope ref. Spec §2.1 says subject assent is proven via EIP-712 / WebAuthn,
///      so the module recovers the subject on-chain and rejects the submission unless
///      the recovered address equals the PDA-configured `subjectSigner`. Without this,
///      the trusted caller (ConditionEngine) could assert any non-empty envelope bytes
///      and forge subject assent — the terminal state drives the Round 2 shred-trigger
///      and reveal ceremonies (S2-6 §11.1), so a forged action is a release/destruction
///      authorization. The domain separator mixes `block.chainid` + `address(this)` so a
///      signature is non-replayable across chains / contracts (S2-2 §15.2). The subject
///      signer is PDA-configurable (platform principle: nothing hardcoded) and epoch-
///      cleared on reconfigure so a rotated subject key cannot sign.
contract SubjectInitiatedModule is ConditionModuleBase, ISubjectInitiatedModule {
    struct SubjectActionState {
        CeremonyAxis expectedAxis;
        bytes32 lastActionDigest;
        uint256 highWaterNonce;
        bool terminal;
        // B3a: the PDA-configured subject signer is keyed by the per-authorizationId
        // epoch so a reconfigure deterministically rotates the eligible signer.
        uint32 epoch;
    }

    /// @dev EIP-712 domain (S2-2 §1.6 / §15.1): name `CealisSubjectInitiated`, version `1`.
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisSubjectInitiated");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    /// @dev `SubjectAction(bytes32 authorizationId,bytes32 actionDigest,address subject)`.
    bytes32 private constant _SUBJECT_ACTION_TYPEHASH =
        keccak256("SubjectAction(bytes32 authorizationId,bytes32 actionDigest,address subject)");

    mapping(bytes32 => SubjectActionState) private _actions;
    mapping(bytes32 => mapping(uint256 => bool)) private _consumedNonces;
    // B3a: the eligible subject signer is keyed by the per-authorizationId epoch so a
    // reconfigure deterministically clears the prior signer without unbounded loops.
    mapping(bytes32 => mapping(uint32 => address)) private _subjectSigner;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
    }

    /// @notice Configures the subject-initiated condition: ceremony axis + the
    ///         PDA-configured subject signer whose EIP-712 assent unlocks the action.
    /// @dev Access: onlyConditionEngineOrModuleAdmin. `subjectSigner` is the address
    ///      whose EIP-712 / WebAuthn-anchored signature is required (spec §2.1).
    ///      B3a: re-configuration BUMPS the per-authorizationId epoch, which atomically
    ///      rotates the eligible subject signer (keyed by epoch) so a prior / compromised
    ///      subject key can no longer submit.
    function configureSubjectInitiated(
        bytes32 authorizationId,
        CeremonyAxis expectedAxis,
        address subjectSigner,
        bytes32 configDigest
    ) external onlyConditionEngineOrModuleAdmin {
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: configDigest, configDigest: configDigest });
        SubjectActionState storage state = _actions[authorizationId];
        uint32 epoch = state.epoch + 1;
        state.expectedAxis = expectedAxis;
        state.epoch = epoch;
        _subjectSigner[authorizationId][epoch] = subjectSigner;
        emit ModuleConfigured(authorizationId, configDigest, configDigest);
    }

    /// @notice Submits a subject-signed action (used by Round 2 shred-trigger flow).
    /// @dev Contract-only (onlyConditionEngine). Validates: (a) configured axis matches,
    ///      (b) not expired, (c) nonce not previously consumed (replay protection),
    ///      (d) `signature` is an EIP-712 signature over the `SubjectAction` typed data
    ///      whose recovered signer equals the PDA-configured subject signer (SC-F-06).
    ///      Sets terminal=true. Pairs with M7 ShredTriggerCeremony for Round 2 (subject
    ///      authority-mode per S2-6 §11.1).
    /// @param authorizationId target PDA authorization.
    /// @param axis CeremonyAxis.Reveal or CeremonyAxis.Shred (must match configured).
    /// @param actionDigest hash of the subject's action evidence.
    /// @param signature EIP-712 signature (65 bytes) over the `SubjectAction` typed data;
    ///        the recovered address MUST equal the configured subject signer (SC-F-06).
    /// @param nonce unique nonce for replay protection (high-water tracked).
    /// @param expiresAt UTC timestamp after which submission is invalid (0 = no expiry).
    function submitSubjectInitiated(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 actionDigest,
        bytes calldata signature,
        uint256 nonce,
        uint64 expiresAt
    ) external onlyConditionEngine {
        _submitSubjectInitiated(authorizationId, axis, actionDigest, signature, nonce, expiresAt);
    }

    function subjectActionState(bytes32 authorizationId) external view returns (SubjectActionState memory) {
        _requireKnown(authorizationId);
        return _actions[authorizationId];
    }

    /// @notice Returns the PDA-configured subject signer for the current epoch.
    /// @dev View. Used by off-chain S2-3 SDK / subject dashboards to bind the
    ///      `CealisSubjectInitiated` typed-data signer before submission.
    function subjectSigner(bytes32 authorizationId) external view returns (address) {
        _requireKnown(authorizationId);
        return _subjectSigner[authorizationId][_actions[authorizationId].epoch];
    }

    function nonceConsumed(bytes32 authorizationId, uint256 nonce) external view returns (bool) {
        return _consumedNonces[authorizationId][nonce];
    }

    function _configureModule(bytes32 authorizationId, bytes32, bytes calldata config, bytes32) internal override {
        CeremonyAxis axis = CeremonyAxis.Reveal;
        address signer = address(0);
        if (config.length != 0) (axis, signer) = abi.decode(config, (CeremonyAxis, address));
        SubjectActionState storage state = _actions[authorizationId];
        uint32 epoch = state.epoch + 1;
        state.expectedAxis = axis;
        state.epoch = epoch;
        _subjectSigner[authorizationId][epoch] = signer;
    }

    function _advanceModule(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        internal
        override
        returns (bool)
    {
        if (proof.length != 0) {
            (CeremonyAxis axis, bytes32 actionDigest, bytes memory signature, uint256 nonce, uint64 expiresAt) =
                abi.decode(proof, (CeremonyAxis, bytes32, bytes, uint256, uint64));
            _submitSubjectInitiated(authorizationId, axis, actionDigest, signature, nonce, expiresAt);
        }
        bool terminal = _actions[authorizationId].terminal && _actions[authorizationId].lastActionDigest == evidenceRef;
        if (!terminal) revert ModuleConditionFalse(authorizationId);
        return true;
    }

    function _evaluateModule(bytes32 authorizationId, bytes32 contextRef) internal view override returns (bool) {
        SubjectActionState memory state = _actions[authorizationId];
        return state.terminal && (contextRef == bytes32(0) || contextRef == state.lastActionDigest);
    }

    function _submitSubjectInitiated(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 actionDigest,
        bytes memory signature,
        uint256 nonce,
        uint64 expiresAt
    ) private {
        _requireKnown(authorizationId);
        _requireNotPaused(authorizationId);
        SubjectActionState storage state = _actions[authorizationId];
        if (axis != state.expectedAxis) revert SubjectInitiatedAxisMismatch(authorizationId, state.expectedAxis, axis);
        if (expiresAt != 0 && block.timestamp > expiresAt) revert SubjectInitiatedExpired(authorizationId, expiresAt);
        if (_consumedNonces[authorizationId][nonce]) revert SubjectInitiatedNonceConsumed(authorizationId, nonce);
        if (actionDigest == bytes32(0)) revert SubjectInitiatedInvalidSigner(authorizationId);
        // SC-F-06: recover the EIP-712 subject signer and require it to equal the
        // PDA-configured subject signer for the current epoch. The trusted caller
        // cannot fabricate subject assent with an arbitrary envelope. tryRecover is used
        // (not recover) so malformed / wrong-length signatures fail closed to address(0)
        // and surface this module's own invalid-signer error, never an OZ revert.
        address expectedSigner = _subjectSigner[authorizationId][state.epoch];
        bytes32 digest = _subjectActionTypedDataHash(authorizationId, actionDigest, expectedSigner);
        (address recovered,,) = ECDSA.tryRecover(digest, signature);
        if (expectedSigner == address(0) || recovered != expectedSigner) {
            revert SubjectInitiatedInvalidSigner(authorizationId);
        }
        _consumedNonces[authorizationId][nonce] = true;
        if (nonce > state.highWaterNonce) state.highWaterNonce = nonce;
        state.lastActionDigest = actionDigest;
        state.terminal = true;
        emit SubjectActionAccepted(authorizationId, axis, actionDigest, nonce);
    }

    /// @dev EIP-712 digest over the `SubjectAction` struct. Self-contained (no shared lib)
    ///      so this module owns its `CealisSubjectInitiated` domain. Domain separator binds
    ///      `block.chainid` + `address(this)` → cross-chain / cross-contract replay rejected
    ///      (S2-2 §15.2).
    function _subjectActionTypedDataHash(bytes32 authorizationId, bytes32 actionDigest, address subject)
        private
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid, address(this)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_SUBJECT_ACTION_TYPEHASH, authorizationId, actionDigest, subject));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    uint256[49] private __gap;
}
