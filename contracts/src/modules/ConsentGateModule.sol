// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { IConsentGateModule } from "../engine/IConditionEngine.sol";
import { ConditionModuleBase } from "./PaymentObligationModule.sol";

/// @dev SC-F-06: each consent carries an EIP-712 typed-data signature
///      (`CealisConsentGate` domain, S2-2 §1.6 / §15.1). The module recovers the
///      authority on-chain and rejects the submission unless the recovered address
///      equals the claimed `authority`. Without this, the trusted caller
///      (ConditionEngine) could assert any allow-listed authority with arbitrary
///      envelope bytes and forge k-of-n consensus. The domain separator mixes
///      `block.chainid` so a signature is non-replayable across chains (S2-2 §15.2).
contract ConsentGateModule is ConditionModuleBase, IConsentGateModule {
    struct ConsentState {
        bytes32 expectedConsentDigest;
        bytes32 authorityRoot;
        uint16 threshold;
        uint16 count;
        uint64 expiresAt;
        bool consumed;
        uint32 epoch;
    }

    /// @dev EIP-712 domain (S2-2 §1.6 / §15.1): name `CealisConsentGate`, version `1`.
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisConsentGate");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    /// @dev `Consent(bytes32 authorizationId,bytes32 consentDigest,address authority)`.
    bytes32 private constant _CONSENT_TYPEHASH =
        keccak256("Consent(bytes32 authorizationId,bytes32 consentDigest,address authority)");

    mapping(bytes32 => ConsentState) private _consents;
    // B3a: eligibility + consented state are keyed by the per-authorizationId epoch so a
    // reconfigure deterministically clears the prior authority set without unbounded loops.
    mapping(bytes32 => mapping(uint32 => mapping(address => bool))) private _eligibleAuthority;
    mapping(bytes32 => mapping(uint32 => mapping(address => bool))) private _consented;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
    }

    /// @dev B3a: re-configuration BUMPS the per-authorizationId epoch, which atomically
    ///      clears any prior authority eligibility, consent count, and per-authority
    ///      consented flags (all keyed by epoch) before the new authority set is populated.
    ///      A rotated-out / compromised authority can no longer submit consent.
    function configureConsent(
        bytes32 authorizationId,
        bytes32 expectedConsentDigest,
        address[] calldata authorities,
        uint16 threshold,
        uint64 expiresAt,
        bytes32 configDigest
    ) external onlyConditionEngineOrModuleAdmin {
        if (threshold == 0 || threshold > authorities.length) {
            revert ConsentAuthorityIneligible(authorizationId, address(0));
        }
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: expectedConsentDigest, configDigest: configDigest });
        uint32 epoch = _consents[authorizationId].epoch + 1;
        _consents[authorizationId] = ConsentState({
            expectedConsentDigest: expectedConsentDigest,
            authorityRoot: keccak256(abi.encode(authorities)),
            threshold: threshold,
            count: 0,
            expiresAt: expiresAt,
            consumed: false,
            epoch: epoch
        });
        for (uint256 i = 0; i < authorities.length; ++i) {
            _eligibleAuthority[authorizationId][epoch][authorities[i]] = true;
        }
        emit ModuleConfigured(authorizationId, expectedConsentDigest, configDigest);
    }

    /// @notice Submits one party's consent toward the k-of-n threshold.
    /// @dev Contract-only (onlyConditionEngine). Predicate evaluates true when
    ///      count >= threshold AND not expired AND not previously consumed AND each
    ///      submitter is on the eligible-authority list AND each consentDigest matches
    ///      the configured expectedConsentDigest. Multi-party signal pattern — M&A
    ///      deal PDA archetype primary use-case.
    /// @param authorizationId target PDA authorization.
    /// @param authority address of the consenting party.
    /// @param consentDigest hash of the consent evidence (must match expectedConsentDigest).
    /// @param signature EIP-712 signature (65 bytes) over the `Consent` typed data;
    ///        the recovered address MUST equal `authority` (SC-F-06).
    /// @param proof reserved (currently passed through).
    function submitConsent(
        bytes32 authorizationId,
        address authority,
        bytes32 consentDigest,
        bytes calldata signature,
        bytes calldata proof
    ) external onlyConditionEngine {
        // @dev `proof` currently reserved — passed through to maintain ABI shape with
        //      other condition modules; future use for non-Cealis attestation proofs.
        proof;
        _submitConsent(authorizationId, authority, consentDigest, signature);
    }

    function consentState(bytes32 authorizationId) external view returns (ConsentState memory) {
        _requireKnown(authorizationId);
        return _consents[authorizationId];
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32)
        internal
        override
    {
        (uint16 threshold, address[] memory authorities, uint64 expiresAt) =
            abi.decode(config, (uint16, address[], uint64));
        if (threshold == 0 || threshold > authorities.length) {
            revert ConsentAuthorityIneligible(authorizationId, address(0));
        }
        uint32 epoch = _consents[authorizationId].epoch + 1;
        _consents[authorizationId] = ConsentState({
            expectedConsentDigest: moduleRef,
            authorityRoot: keccak256(abi.encode(authorities)),
            threshold: threshold,
            count: 0,
            expiresAt: expiresAt,
            consumed: false,
            epoch: epoch
        });
        for (uint256 i = 0; i < authorities.length; ++i) {
            _eligibleAuthority[authorizationId][epoch][authorities[i]] = true;
        }
    }

    function _advanceModule(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        internal
        override
        returns (bool)
    {
        if (proof.length != 0) {
            (address authority, bytes memory signature) = abi.decode(proof, (address, bytes));
            _submitConsent(authorizationId, authority, evidenceRef, signature);
        }
        ConsentState memory state = _consents[authorizationId];
        if (state.count < state.threshold) revert ModuleConditionFalse(authorizationId);
        return true;
    }

    function _evaluateModule(bytes32 authorizationId, bytes32 contextRef) internal view override returns (bool) {
        ConsentState memory state = _consents[authorizationId];
        return state.count >= state.threshold && (contextRef == bytes32(0) || contextRef == state.expectedConsentDigest);
    }

    function _submitConsent(
        bytes32 authorizationId,
        address authority,
        bytes32 consentDigest,
        bytes memory signature
    ) private {
        _requireKnown(authorizationId);
        _requireNotPaused(authorizationId);
        ConsentState storage state = _consents[authorizationId];
        if (state.expiresAt != 0 && block.timestamp > state.expiresAt) {
            revert ConsentExpired(authorizationId, state.expiresAt);
        }
        if (consentDigest != state.expectedConsentDigest) {
            revert ConsentDigestMismatch(authorizationId, state.expectedConsentDigest, consentDigest);
        }
        uint32 epoch = state.epoch;
        if (!_eligibleAuthority[authorizationId][epoch][authority] || signature.length == 0) {
            revert ConsentAuthorityIneligible(authorizationId, authority);
        }
        // SC-F-06: recover the EIP-712 signer and require it to equal the claimed `authority`.
        // The trusted caller cannot fabricate consent on behalf of an allow-listed party.
        // tryRecover is used (not recover) so malformed / wrong-length signatures fail closed
        // to address(0) and surface this module's own ineligible error, never an OZ revert.
        bytes32 digest = _consentTypedDataHash(authorizationId, consentDigest, authority);
        (address recovered,,) = ECDSA.tryRecover(digest, signature);
        if (recovered != authority) {
            revert ConsentAuthorityIneligible(authorizationId, authority);
        }
        if (!_consented[authorizationId][epoch][authority]) {
            _consented[authorizationId][epoch][authority] = true;
            state.count += 1;
        }
        if (state.count >= state.threshold) state.consumed = true;
        emit ConsentAccepted(authorizationId, bytes32(uint256(uint160(authority))), consentDigest);
    }

    /// @dev EIP-712 digest over the `Consent` struct. Self-contained (no shared lib) so this
    ///      module owns its `CealisConsentGate` domain. Domain separator binds `block.chainid`
    ///      + `address(this)` → cross-chain / cross-contract replay rejected (S2-2 §15.2).
    function _consentTypedDataHash(bytes32 authorizationId, bytes32 consentDigest, address authority)
        private
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid, address(this)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_CONSENT_TYPEHASH, authorizationId, consentDigest, authority));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    uint256[50] private __gap;
}
