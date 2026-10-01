// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ICealisIdentifierHelpers } from "./ICealisIdentifierHelpers.sol";
import { Tags } from "../lib/Tags.sol";
import { PdaRootFields, HCommitFields } from "../lib/Structs.sol";

/// @title CealisIdentifierHelpers - byte-exact V3 composite-identifier helpers
/// @notice Concrete pure-helper contract implementing `ICealisIdentifierHelpers`.
///         Every helper produces output byte-identical to the M1 reference at
///         `v3-crypto/src/`. The Foundry differential test
///         `test/foundation/CealisIdentifierHelpers.t.sol` loads the M1 golden
///         vectors and asserts equality.
///
/// @dev `abi.encodePacked` produces fixed-width big-endian encoding for
///      unsigned integer types (uint8 = 1B, uint16 = 2B BE, uint32 = 4B BE,
///      uint64 = 8B BE) and 1-byte 0x00/0x01 for `bool` - this matches M1's
///      `boolByte()`, `u64BE()`, `u32BE()`, `u16BE()` helpers exactly.
contract CealisIdentifierHelpers is ICealisIdentifierHelpers {
    /// @notice Computes the subject commitment v3 from a 3-tuple.
    /// @dev S2-1 §3.1.1: 128-byte preimage (TAG_SUBJECT_V3 || personKey ||
    ///      partnerNamespace || registrationNonce). PRIVACY-CRITICAL: distinct
    ///      partnerNamespace yields distinct subjectCommitment, preventing
    ///      cross-partner linkability — same person, different partners, NO
    ///      observable correlation on-chain. Fuzz-tested by
    ///      testFuzz_subjectCommitment_isCollisionResistant + testFuzz_subjectCommitment_isDeterministic
    ///      (commit 85dc386). Also addresses V1 PRO-226 cross-partner linkability concern.
    /// @inheritdoc ICealisIdentifierHelpers
    function computeSubjectCommitmentV3(bytes32 personKey, bytes32 partnerNamespace, bytes32 registrationNonce)
        external
        pure
        override
        returns (bytes32)
    {
        // S2-1 §3.1.1: keccak256(TAG_SUBJECT_V3 ‖ person_key ‖ partner_namespace ‖ registration_nonce)
        // preimage = 32 + 32 + 32 + 32 = 128 bytes
        return keccak256(abi.encodePacked(Tags.TAG_SUBJECT_V3, personKey, partnerNamespace, registrationNonce));
    }

    /// @notice Computes the 32-byte authorizationId from the 5-tuple.
    /// @dev S2-1 §3.2.1: 144-byte preimage (TAG_AUTHID_V3 || subjectCommitmentV3 ||
    ///      pdaId || pdaVersion(8B BE) || epoch(8B BE) || nonce). Pure function.
    ///      Fuzz-tested by testFuzz_authorizationId_matchesTagPrefixedHash +
    ///      testFuzz_authorizationId_isCollisionResistant (commit 80e25f8).
    /// @inheritdoc ICealisIdentifierHelpers
    function computeAuthorizationId(
        bytes32 subjectCommitmentV3,
        bytes32 pdaId,
        uint64 pdaVersion,
        uint64 epoch,
        bytes32 nonce
    ) external pure override returns (bytes32) {
        // S2-1 §3.2.1: keccak256(TAG_AUTHID_V3 ‖ subject_commitment_v3 ‖ pda_id ‖ pda_version(8B BE) ‖ epoch(8B BE) ‖ nonce)
        // preimage = 32 + 32 + 32 + 8 + 8 + 32 = 144 bytes
        return keccak256(abi.encodePacked(Tags.TAG_AUTHID_V3, subjectCommitmentV3, pdaId, pdaVersion, epoch, nonce));
    }

    /// @notice Computes the PDA root hash from the 29-field PdaRootFields struct.
    /// @dev S2-1 §3.3.1: 540-byte preimage. TAG-prefixed (TAG_PDA_ROOT_V3) keccak.
    ///      Field order MUST match M1 `v3-crypto/src/codecs/pda-root.ts`
    ///      buildPDARootPreimage() — drift between TS and Solidity here would break
    ///      every commitment verification. Two-stage encode (part1 || part2) is a
    ///      Solidity workaround for the 16-local-variable stack cap (each `bool`
    ///      member counts as a stack slot — there are 13 bool/uint8 D1-additions).
    /// @inheritdoc ICealisIdentifierHelpers
    function computePdaRoot(PdaRootFields calldata fields) external pure override returns (bytes32) {
        // S2-1 §3.3.1: 540-byte preimage. Field order matches M1
        // v3-crypto/src/codecs/pda-root.ts buildPDARootPreimage().
        // Two-stage encode keeps the abi.encodePacked stack within Solidity's
        // 16-local-variable cap (each `bool` member counts as a stack slot).
        bytes memory part1 = abi.encodePacked(
            Tags.TAG_PDA_ROOT_V3,
            // §3.3.3 - original 16 fields
            fields.pdaId,
            fields.pdaVersion,
            fields.revealConditionMode,
            fields.revealConditionSpecHash,
            fields.shredConditionMode,
            fields.shredConditionSpecHash,
            fields.oracleReferencesRoot,
            fields.dslVersion,
            fields.wasmPredicateHashesRoot,
            fields.submitterSetsRoot,
            fields.pauseAuthorityId,
            fields.ceremonyResolverId,
            fields.eligibleChallengersRevealRoot,
            fields.eligibleChallengersShredRoot,
            fields.templateId,
            fields.partnerId
        );
        bytes memory part2 = abi.encodePacked(
            // §3.3.4 - 13 D1 additions
            fields.subjectAuthenticatorClass,
            fields.qtspProviderRef,
            fields.art9Scoped,
            fields.art9BasisId,
            fields.legalEffectExpected,
            fields.cealisClassWideHaltOptOut,
            fields.minimumShredLatency,
            fields.applicableJurisdiction,
            fields.conditionalRecipientsUpdatable,
            fields.subjectLivenessRequiredAtFire,
            fields.emergencyResponseBrickingAcknowledgment,
            fields.timeCriticalPdaFlag,
            fields.pdaUpdatable
        );
        return keccak256(bytes.concat(part1, part2));
    }

    /// @notice Computes the commitment hash hCommit from the 15-field HCommitFields struct.
    /// @dev S2-1 §3.4.1: 340-byte preimage after TAG_COMMIT_V3. Field order MUST match
    ///      M1 `v3-crypto/src/codecs/h-commit.ts`. Includes commitVersion
    ///      (uint16) per IB-1 post-fix for cross-version collision protection.
    ///      Verified by `testFuzz_hCommit_isCollisionResistantOnCommitVersion` in
    ///      test/fuzz/CealisIdentifierHelpers.fuzz.t.sol.
    /// @inheritdoc ICealisIdentifierHelpers
    function computeHCommit(HCommitFields calldata fields) external pure override returns (bytes32) {
        // S2-1 §3.4.1: 340-byte preimage of 15 inputs after the TAG.
        // Field order matches App. A struct order = S2-1 §3.4.1 listing.
        return keccak256(
            abi.encodePacked(
                Tags.TAG_COMMIT_V3,
                fields.authorizationId,
                fields.pdaRoot,
                fields.schemaDigest,
                fields.ciphertextDigest,
                fields.aadDigest,
                fields.compositeIdentityDigest,
                fields.endpointAttestationDigest,
                fields.retentionWindow, // uint64 = 8B BE
                fields.shredAuthorityId,
                fields.recipientsRoot,
                fields.revealChallengeWindow, // uint32 = 4B BE
                fields.shredChallengeWindow, // uint32 = 4B BE
                fields.g3Choice, // uint8 = 1B
                fields.phase, // uint8 = 1B
                fields.commitVersion // uint16 = 2B BE
            )
        );
    }

    /// @inheritdoc ICealisIdentifierHelpers
    function computePluginVersionDigest(bytes32 canonicalBinaryHash) external pure override returns (bytes32) {
        // S2-1 §2.3.4 + S2-2 §3.6: keccak256(TAG_PLUGIN_VERSION_V3 ‖ canonicalBinaryHash)
        return keccak256(abi.encodePacked(Tags.TAG_PLUGIN_VERSION_V3, canonicalBinaryHash));
    }

    /// @inheritdoc ICealisIdentifierHelpers
    function computeG4AuthorityRef(bytes calldata authorityPubkey) external pure override returns (bytes32) {
        // S2-1 §2.3.3 + S2-2 §3.6: keccak256(TAG_G4_ATTESTATION_AUTHORITY_V3 ‖ authorityPubkey).
        // authorityPubkey is variable-length but the TAG-prefix + raw bytes
        // construction is permitted because this output is itself a
        // domain-separated digest used as a registry lookup key (its 32-byte
        // form provides the boundary discipline downstream).
        return keccak256(abi.encodePacked(Tags.TAG_G4_ATTESTATION_AUTHORITY_V3, authorityPubkey));
    }

    /// @inheritdoc ICealisIdentifierHelpers
    function computeSupersededCommitLookup(bytes32 supersededCommitRef, uint16 commitGeneration)
        external
        pure
        override
        returns (bytes32)
    {
        // S2-1 §15.6.3: keccak256(TAG_SUPERSEDED_COMMIT_REGISTRY_V3 ‖ superseded_commit_ref ‖ commit_generation)
        // commitGeneration: uint16 BE per S2-1 §1.2 + §15.6.3.
        return
            keccak256(abi.encodePacked(Tags.TAG_SUPERSEDED_COMMIT_REGISTRY_V3, supersededCommitRef, commitGeneration));
    }
}
