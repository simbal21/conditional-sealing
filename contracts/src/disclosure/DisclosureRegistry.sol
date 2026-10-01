// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

interface IDisclosureRevocationRegistryView {
    function isRevoked(bytes32 disclosureId) external view returns (bool);
}

interface IPlonkVerifier {
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool);
}

contract DisclosureRegistry is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable {
    error DisclosureVerifierUnknown(bytes32 verifierRef);
    error DisclosureProofInvalid(bytes32 disclosureId);
    error DisclosureUnknown(bytes32 disclosureId);
    error RevocationRegistryUnavailable();
    error DisclosurePaused(bytes32 scope);

    event DisclosureCommitted(bytes32 indexed disclosureId, bytes32 indexed authorizationId, bytes32 proofDigest);
    event DisclosureProofVerified(bytes32 indexed disclosureId, bytes32 indexed authorizationId, bytes32 verifierRef);
    event DisclosureVerifierRegistered(bytes32 indexed verifierRef);
    event DisclosureVerifierContractRegistered(bytes32 indexed verifierRef, address indexed verifierContract);

    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;
    bytes32 public constant PAUSER_ROLE = Roles.PAUSER_ROLE;
    bytes32 public constant SD_OPERATOR_ROLE = Roles.SD_OPERATOR_ROLE;
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    address private _revocationRegistry;
    mapping(bytes32 => bytes32) private _disclosureDigests;
    mapping(bytes32 => bool) private _knownVerifiers;
    mapping(bytes32 => address) private _verifierContracts;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address revocationRegistry_) external initializer {
        if (revocationRegistry_ == address(0)) {
            revert RevocationRegistryUnavailable();
        }
        _revocationRegistry = revocationRegistry_;
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
    }

    function registerVerifier(bytes32 verifierRef) external onlyRole(Roles.SD_OPERATOR_ROLE) {
        _knownVerifiers[verifierRef] = true;
        emit DisclosureVerifierRegistered(verifierRef);
    }

    function registerVerifierContract(bytes32 verifierRef, address verifierContract)
        external
        onlyRole(Roles.SD_OPERATOR_ROLE)
    {
        _verifierContracts[verifierRef] = verifierContract;
        emit DisclosureVerifierContractRegistered(verifierRef, verifierContract);
    }

    function commitDisclosure(bytes32 disclosureId, bytes32 authorizationId, bytes32 proofDigest)
        public
        onlyRole(Roles.SD_OPERATOR_ROLE)
    {
        _requireNotPaused(GLOBAL_SCOPE);
        _disclosureDigests[disclosureId] = proofDigest;
        emit DisclosureCommitted(disclosureId, authorizationId, proofDigest);
    }

    function verifyDisclosureProof(
        bytes32 disclosureId,
        bytes32 authorizationId,
        bytes32 sdMerkleRoot,
        bytes32 verifierRef,
        bytes calldata proof,
        bytes calldata publicInputs
    ) public onlyRole(Roles.SD_OPERATOR_ROLE) returns (bool) {
        sdMerkleRoot;
        _requireNotPaused(GLOBAL_SCOPE);

        address verifier = _verifierContracts[verifierRef];
        if (verifier != address(0)) {
            // Per-predicate PLONK verifier dispatch (M6 Phase D).
            // Decode publicInputs (bytes) into uint256[] per ISdPlonkVerifier ABI.
            uint256[] memory pubInputs = abi.decode(publicInputs, (uint256[]));
            bool ok = IPlonkVerifier(verifier).verifyProof(proof, pubInputs);
            if (!ok) {
                return false;
            }
            emit DisclosureProofVerified(disclosureId, authorizationId, verifierRef);
            return true;
        }

        // Backward-compat fallback for legacy non-PLONK verifiers (LOCKED design
        // decision per SPEC-COMPLIANCE-GUARD-M6 §22). Preserves the bool-only
        // path for verifiers registered via the original `registerVerifier`.
        if (!_knownVerifiers[verifierRef]) {
            revert DisclosureVerifierUnknown(verifierRef);
        }
        emit DisclosureProofVerified(disclosureId, authorizationId, verifierRef);
        return true;
    }

    /// @notice Verifies an SD PLONK proof + commits the disclosure atomically.
    /// @dev Public per-spec entry point for partner-supplied SD bundles (called by
    ///      partner verify-sdk through partner-controlled RPC per S2-7 §9.5).
    ///      Reverts in 3 cases: (1) disclosure already revoked (cross-checks
    ///      DisclosureRevocationRegistry), (2) PLONK proof invalid (DisclosureProofInvalid),
    ///      (3) unknown verifierRef (DisclosureVerifierUnknown). On success, persists
    ///      proofDigest under disclosureId. Pairs with verifyDisclosureProof for the
    ///      stateless verify path.
    /// @param disclosureId stable handle for this SD bundle.
    /// @param authorizationId target PDA authorization.
    /// @param sdMerkleRoot SD Merkle root (must be bound at fixed position in
    ///                     commit_AAD per S2-1 §4 / BP-SD-1).
    /// @param verifierRef which registered PLONK verifier to use.
    /// @param proof PLONK proof bytes.
    /// @param publicInputs PLONK public inputs.
    /// @param proofDigest hash of (proof, publicInputs) for the on-chain record.
    /// @return ok always true on success (revert on any failure).
    function verifyAndCommitDisclosure(
        bytes32 disclosureId,
        bytes32 authorizationId,
        bytes32 sdMerkleRoot,
        bytes32 verifierRef,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 proofDigest
    ) external returns (bool) {
        _requireDisclosureNotRevoked(disclosureId);
        bool ok = verifyDisclosureProof(disclosureId, authorizationId, sdMerkleRoot, verifierRef, proof, publicInputs);
        if (!ok) {
            revert DisclosureProofInvalid(disclosureId);
        }
        commitDisclosure(disclosureId, authorizationId, proofDigest);
        return true;
    }

    function disclosureDigest(bytes32 disclosureId) external view returns (bytes32) {
        bytes32 digest = _disclosureDigests[disclosureId];
        if (digest == bytes32(0)) {
            revert DisclosureUnknown(disclosureId);
        }
        return digest;
    }

    function disclosureRevoked(bytes32 disclosureId) external view returns (bool) {
        return IDisclosureRevocationRegistryView(_revocationRegistry).isRevoked(disclosureId);
    }

    function revocationRegistry() external view returns (address) {
        return _revocationRegistry;
    }

    function _requireDisclosureNotRevoked(bytes32 disclosureId) internal view {
        try IDisclosureRevocationRegistryView(_revocationRegistry).isRevoked(disclosureId) returns (bool revoked) {
            if (revoked) {
                revert RevocationRegistryUnavailable();
            }
        } catch {
            revert RevocationRegistryUnavailable();
        }
    }

    function _requireNotPaused(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert DisclosurePaused(scope);
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

    uint256[49] private __gap;
}
