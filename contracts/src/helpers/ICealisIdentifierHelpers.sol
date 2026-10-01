// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { PdaRootFields, HCommitFields } from "../lib/Structs.sol";

/// @title ICealisIdentifierHelpers - byte-exact composite-identifier helpers
/// @notice Mirrored verbatim from S2-2 App. A lines 2222-2252.
///
///         All helpers are pure / view and must produce byte-identical
///         output to the M1 reference at `v3-crypto/src/`:
///           - `subject_commitment_v3` ↔ `codecs/subject-commitment.ts`
///           - `authorizationId`        ↔ `codecs/auth-id.ts` (if present)
///                                        OR direct byte-concat per S2-1 §3.2
///           - `pda_root`               ↔ `codecs/pda-root.ts`
///           - `h_commit`               ↔ `codecs/commit-aad.ts` h_commit shape
///           - `plugin_version_digest`  ↔ `codecs/plugin-version.ts` (if present)
///           - `g4_authority_ref`       ↔ S2-1 §2.3.3 byte-concat
///           - `superseded_commit_lookup` ↔ S2-1 §2.3.4 + §15.6.3
///
/// @dev TAG imports per S2-1 §2.3.x are documented in the per-function NatSpec.
interface ICealisIdentifierHelpers {
    /// @notice subject_commitment_v3 = keccak256(TAG_SUBJECT_V3 ‖ personKey ‖ partnerNamespace ‖ registrationNonce)
    /// @dev Imports TAG_SUBJECT_V3 from S2-1 §2.3.1. Per S2-1 §3.1.1
    ///      preimage = 32 (TAG) + 32 + 32 + 32 = 128 bytes.
    function computeSubjectCommitmentV3(bytes32 personKey, bytes32 partnerNamespace, bytes32 registrationNonce)
        external
        pure
        returns (bytes32);

    /// @notice authorizationId = keccak256(TAG_AUTHID_V3 ‖ subjectCommitmentV3 ‖ pdaId ‖ pdaVersion ‖ epoch ‖ nonce)
    /// @dev Imports TAG_AUTHID_V3 from S2-1 §2.3.1. Per S2-1 §3.2.1
    ///      preimage = 32 + 32 + 32 + 8 + 8 + 32 = 144 bytes.
    function computeAuthorizationId(
        bytes32 subjectCommitmentV3,
        bytes32 pdaId,
        uint64 pdaVersion,
        uint64 epoch,
        bytes32 nonce
    ) external pure returns (bytes32);

    /// @notice pda_root = keccak256(TAG_PDA_ROOT_V3 ‖ <540-byte preimage of 29 fields>)
    /// @dev Imports TAG_PDA_ROOT_V3 from S2-1 §2.3.1 and S2-1 §3.3 field order.
    ///      Conditional binding rule (D1 normative): every field appears in the
    ///      preimage regardless of value.
    function computePdaRoot(PdaRootFields calldata fields) external pure returns (bytes32);

    /// @notice h_commit = keccak256(TAG_COMMIT_V3 ‖ <340-byte preimage of 15 fields>)
    /// @dev Imports TAG_COMMIT_V3 from S2-1 §2.3.1 and S2-1 §3.4 field order.
    ///      Per S2-2 §3.5 helper accepts phase ∈ {1, 2}; PDA registration
    ///      validators reject phase==1 for legal-effect PDAs but the helper
    ///      itself stays capable of historical reconstruction.
    function computeHCommit(HCommitFields calldata fields) external pure returns (bytes32);

    /// @notice plugin_version_digest = keccak256(TAG_PLUGIN_VERSION_V3 ‖ canonicalBinaryHash)
    /// @dev Imports TAG_PLUGIN_VERSION_V3 from S2-1 §2.3.4.
    function computePluginVersionDigest(bytes32 canonicalBinaryHash) external pure returns (bytes32);

    /// @notice g4_authority_ref = keccak256(TAG_G4_ATTESTATION_AUTHORITY_V3 ‖ authorityPubkey)
    /// @dev Imports TAG_G4_ATTESTATION_AUTHORITY_V3 from S2-1 §2.3.3.
    ///      authorityPubkey is variable-length; preimage discipline is
    ///      TAG-prefix + raw bytes per S2-1 §1.3.1 (the `bytes` arg is
    ///      already length-disambiguated by being its own keccak input).
    function computeG4AuthorityRef(bytes calldata authorityPubkey) external pure returns (bytes32);

    /// @notice superseded_commit_lookup = keccak256(TAG_SUPERSEDED_COMMIT_REGISTRY_V3 ‖ supersededCommitRef ‖ commitGeneration)
    /// @dev Imports TAG_SUPERSEDED_COMMIT_REGISTRY_V3 from S2-1 §2.3.4 and §15.6.3.
    ///      commitGeneration is uint16, encoded big-endian per S2-1 §1.2.
    function computeSupersededCommitLookup(bytes32 supersededCommitRef, uint16 commitGeneration)
        external
        pure
        returns (bytes32);
}
