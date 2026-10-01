// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { IMultiPartySignalModule } from "../engine/IConditionEngine.sol";
import { ConditionModuleBase } from "./PaymentObligationModule.sol";

/// @title MultiPartySignalModule - k-of-n party signal aggregation
/// @notice One of the 9 ConditionEngine modules. Predicate fires when at least
///         `threshold` of `signerCount` eligible parties have submitted a
///         signature on the same signalDigest. Drives use cases: court-order
///         multi-judge endorsement, M&A signatory threshold (e.g., "5 of 8 board
///         members sign release"), DAO governance multi-sig, cross-jurisdictional
///         regulator consortium signal.
/// @dev Distinct from ConsentGateModule: ConsentGate is single-consent on one
///      fixed digest; this module supports MULTIPLE distinct signalDigests in
///      parallel — each gets its own count, useful for "any of N proposed
///      actions" patterns. Duplicate-signer guard prevents one party from
///      double-counting; expiresAt allows time-bounded signal windows.
/// @dev SC-F-06: each submitted signal carries an EIP-712 typed-data signature
///      (`CealisMultiPartySignal` domain, S2-2 §1.6 / §15.1). The module recovers
///      the signer on-chain and rejects the submission unless the recovered
///      address equals the claimed `signer`. Without this, the trusted caller
///      (ConditionEngine) could assert any allow-listed signer with arbitrary
///      envelope bytes and forge k-of-n consensus. The domain separator mixes
///      `block.chainid` so a signature is non-replayable across chains (S2-2 §15.2).
contract MultiPartySignalModule is ConditionModuleBase, IMultiPartySignalModule {
    struct SignalConfig {
        bytes32 expectedSignalDigest;
        uint16 threshold;
        uint16 signerCount;
        uint64 expiresAt;
        uint32 epoch;
    }

    /// @dev EIP-712 domain (S2-2 §1.6 / §15.1): name `CealisMultiPartySignal`, version `1`.
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisMultiPartySignal");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    /// @dev `Signal(bytes32 authorizationId,bytes32 signalDigest,address signer)`.
    bytes32 private constant _SIGNAL_TYPEHASH =
        keccak256("Signal(bytes32 authorizationId,bytes32 signalDigest,address signer)");

    mapping(bytes32 => SignalConfig) private _signalConfigs;
    // B3a: eligibility + submitted state are keyed by the per-authorizationId epoch so a
    // reconfigure deterministically clears the prior signer set without unbounded loops.
    mapping(bytes32 => mapping(uint32 => mapping(address => bool))) private _eligibleSigner;
    mapping(bytes32 => mapping(uint32 => mapping(bytes32 => uint16))) private _signalCounts;
    mapping(bytes32 => mapping(uint32 => mapping(bytes32 => mapping(address => bool)))) private _submitted;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
    }

    /// @notice Configures the k-of-n multi-party signal condition.
    /// @dev Access: onlyConditionEngineOrModuleAdmin. Threshold MUST be in
    ///      [1, signers.length] — reverts MultiPartySignalThresholdNotMet
    ///      otherwise. signers[] populates the eligible-signer allow-list (only
    ///      these addresses' signatures count). expiresAt=0 means no expiry;
    ///      otherwise post-expiry submissions revert ModuleConditionFalse.
    ///      B3a: re-configuration BUMPS the per-authorizationId epoch, which
    ///      atomically clears any prior signer eligibility, signal counts, and
    ///      duplicate-submission flags (keyed by epoch) before the new signer set
    ///      is populated. A rotated-out / compromised signer can no longer submit.
    function configureSignal(
        bytes32 authorizationId,
        bytes32 signalDigest,
        address[] calldata signers,
        uint16 threshold,
        uint64 expiresAt,
        bytes32 configDigest
    ) external onlyConditionEngineOrModuleAdmin {
        if (threshold == 0 || threshold > signers.length) {
            revert MultiPartySignalThresholdNotMet(authorizationId, 0, threshold);
        }
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: signalDigest, configDigest: configDigest });
        uint32 epoch = _signalConfigs[authorizationId].epoch + 1;
        _signalConfigs[authorizationId] = SignalConfig({
            expectedSignalDigest: signalDigest,
            threshold: threshold,
            signerCount: uint16(signers.length),
            expiresAt: expiresAt,
            epoch: epoch
        });
        for (uint256 i = 0; i < signers.length; ++i) {
            _eligibleSigner[authorizationId][epoch][signers[i]] = true;
        }
        emit ModuleConfigured(authorizationId, signalDigest, configDigest);
    }

    /// @notice Records one party's signal toward the k-of-n threshold for a given
    ///         signalDigest.
    /// @dev Contract-only (onlyConditionEngine). Variant of ConsentGate: predicate
    ///      evaluates true when count(signers for digest D) >= threshold AND each
    ///      signer is on the eligible-signer list. Distinguishes from ConsentGate
    ///      by allowing MULTIPLE distinct signalDigests in parallel (each gets its
    ///      own count); useful for "any of N proposed actions" patterns vs
    ///      ConsentGate's "single consent on one fixed digest."
    /// @param signature EIP-712 signature (65 bytes) over the `Signal` typed data;
    ///        the recovered address MUST equal `signer` (SC-F-06).
    function submitSignal(
        bytes32 authorizationId,
        address signer,
        bytes32 signalDigest,
        bytes calldata signature,
        bytes calldata proof
    ) external onlyConditionEngine {
        proof;
        _submitSignal(authorizationId, signer, signalDigest, signature);
    }

    /// @notice Returns (current count, threshold) for a given signalDigest.
    /// @dev View. count >= threshold means the predicate would fire. Per-digest
    ///      counters allow parallel signal threads on the same authorizationId.
    function signalCount(bytes32 authorizationId, bytes32 signalDigest)
        external
        view
        returns (uint16 count, uint16 threshold)
    {
        SignalConfig memory config = _signalConfigs[authorizationId];
        return (_signalCounts[authorizationId][config.epoch][signalDigest], config.threshold);
    }

    /// @notice Returns the full SignalConfig (expected digest, threshold, signerCount, expiresAt, epoch).
    /// @dev View. Reverts if authorizationId is unknown. Used by off-chain
    ///      indexers + signer dashboards to display threshold-progress UI.
    function signalConfig(bytes32 authorizationId) external view returns (SignalConfig memory) {
        _requireKnown(authorizationId);
        return _signalConfigs[authorizationId];
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32)
        internal
        override
    {
        (uint16 threshold, address[] memory signers, uint64 expiresAt) = abi.decode(config, (uint16, address[], uint64));
        if (threshold == 0 || threshold > signers.length) {
            revert MultiPartySignalThresholdNotMet(authorizationId, 0, threshold);
        }
        uint32 epoch = _signalConfigs[authorizationId].epoch + 1;
        _signalConfigs[authorizationId] = SignalConfig({
            expectedSignalDigest: moduleRef,
            threshold: threshold,
            signerCount: uint16(signers.length),
            expiresAt: expiresAt,
            epoch: epoch
        });
        for (uint256 i = 0; i < signers.length; ++i) {
            _eligibleSigner[authorizationId][epoch][signers[i]] = true;
        }
    }

    function _advanceModule(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        internal
        override
        returns (bool)
    {
        if (proof.length != 0) {
            (address signer, bytes memory signature) = abi.decode(proof, (address, bytes));
            _submitSignal(authorizationId, signer, evidenceRef, signature);
        }
        SignalConfig memory config = _signalConfigs[authorizationId];
        uint16 count = _signalCounts[authorizationId][config.epoch][evidenceRef];
        if (count < config.threshold) {
            revert MultiPartySignalThresholdNotMet(authorizationId, count, config.threshold);
        }
        emit MultiPartySignalThresholdMet(authorizationId, evidenceRef, count, config.threshold);
        return true;
    }

    function _evaluateModule(bytes32 authorizationId, bytes32 contextRef) internal view override returns (bool) {
        SignalConfig memory config = _signalConfigs[authorizationId];
        bytes32 signalDigest = contextRef == bytes32(0) ? config.expectedSignalDigest : contextRef;
        return _signalCounts[authorizationId][config.epoch][signalDigest] >= config.threshold;
    }

    function _submitSignal(
        bytes32 authorizationId,
        address signer,
        bytes32 signalDigest,
        bytes memory signature
    ) private {
        _requireKnown(authorizationId);
        _requireNotPaused(authorizationId);
        SignalConfig memory config = _signalConfigs[authorizationId];
        if (config.expiresAt != 0 && block.timestamp > config.expiresAt) revert ModuleConditionFalse(authorizationId);
        if (config.expectedSignalDigest != signalDigest) {
            revert MultiPartySignalDigestMismatch(authorizationId, config.expectedSignalDigest, signalDigest);
        }
        if (!_eligibleSigner[authorizationId][config.epoch][signer] || signature.length == 0) {
            revert MultiPartySignalSignerIneligible(authorizationId, signer);
        }
        // SC-F-06: recover the EIP-712 signer and require it to equal the claimed `signer`.
        // The trusted caller cannot fabricate consensus on behalf of an allow-listed party.
        // tryRecover is used (not recover) so malformed / wrong-length signatures fail closed
        // to address(0) and surface this module's own ineligible error, never an OZ revert.
        bytes32 digest = _signalTypedDataHash(authorizationId, signalDigest, signer);
        (address recovered,,) = ECDSA.tryRecover(digest, signature);
        if (recovered != signer) {
            revert MultiPartySignalSignerIneligible(authorizationId, signer);
        }
        if (_submitted[authorizationId][config.epoch][signalDigest][signer]) {
            revert MultiPartySignalDuplicateSigner(authorizationId, signer);
        }
        _submitted[authorizationId][config.epoch][signalDigest][signer] = true;
        _signalCounts[authorizationId][config.epoch][signalDigest] += 1;
        emit SignalSubmitted(authorizationId, signalDigest, signer);
    }

    /// @dev EIP-712 digest over the `Signal` struct. Self-contained (no shared lib) so this
    ///      module owns its `CealisMultiPartySignal` domain. Domain separator binds
    ///      `block.chainid` + `address(this)` → cross-chain / cross-contract replay rejected
    ///      (S2-2 §15.2).
    function _signalTypedDataHash(bytes32 authorizationId, bytes32 signalDigest, address signer)
        private
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid, address(this)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_SIGNAL_TYPEHASH, authorizationId, signalDigest, signer));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    uint256[50] private __gap;
}
