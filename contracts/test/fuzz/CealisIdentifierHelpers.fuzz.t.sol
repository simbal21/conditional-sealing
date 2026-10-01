// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { CealisIdentifierHelpers } from "../../src/helpers/CealisIdentifierHelpers.sol";
import { HCommitFields } from "../../src/lib/Structs.sol";
import { Tags } from "../../src/lib/Tags.sol";

/// @title CealisIdentifierHelpers fuzz suite — domain-separation invariants
/// @notice Advances V3 testing category toward 5/5 per MATURITY-SCORECARD.md.
/// @dev Foundry runs each test 256 times per `foundry.toml` `[profile.default.fuzz]`.
contract CealisIdentifierHelpersFuzzTest is Test {
    CealisIdentifierHelpers internal helpers;

    function setUp() public {
        helpers = new CealisIdentifierHelpers();
    }

    /// @notice Two different (personKey, partnerNamespace, registrationNonce) tuples
    ///         MUST produce different subject commitments — collision is a privacy
    ///         break (cross-partner linkability).
    function testFuzz_subjectCommitment_isCollisionResistant(
        bytes32 personKey1,
        bytes32 partnerNs1,
        bytes32 regNonce1,
        bytes32 personKey2,
        bytes32 partnerNs2,
        bytes32 regNonce2
    ) external view {
        vm.assume(personKey1 != personKey2 || partnerNs1 != partnerNs2 || regNonce1 != regNonce2);
        bytes32 a = helpers.computeSubjectCommitmentV3(personKey1, partnerNs1, regNonce1);
        bytes32 b = helpers.computeSubjectCommitmentV3(personKey2, partnerNs2, regNonce2);
        assertTrue(a != b, "subject commitment collision");
    }

    /// @notice Subject commitment is deterministic — same inputs always yield same
    ///         output. Required for cross-session verifiability.
    function testFuzz_subjectCommitment_isDeterministic(
        bytes32 personKey,
        bytes32 partnerNs,
        bytes32 regNonce
    ) external view {
        bytes32 a = helpers.computeSubjectCommitmentV3(personKey, partnerNs, regNonce);
        bytes32 b = helpers.computeSubjectCommitmentV3(personKey, partnerNs, regNonce);
        assertEq(a, b, "subject commitment not deterministic");
    }

    /// @notice TAG-prefixed digests for distinct tag classes MUST differ even with
    ///         identical payloads. Domain-separation guarantee.
    function testFuzz_pluginVersion_vs_subjectCommitment_domainSeparation(bytes32 payload) external view {
        bytes32 pluginDigest = helpers.computePluginVersionDigest(payload);
        bytes32 subjectDigest = helpers.computeSubjectCommitmentV3(payload, payload, payload);
        // Different tag domains must produce different digests for the same payload.
        assertTrue(pluginDigest != subjectDigest, "TAG_PLUGIN_VERSION vs TAG_SUBJECT collision");
    }

    /// @notice G4 authority ref domain-separation: pure function over bytes input.
    ///         Output MUST equal keccak256(TAG_G4_ATTESTATION_AUTHORITY_V3 || authorityPubkey).
    function testFuzz_g4AuthorityRef_matchesTagPrefixedHash(bytes calldata authorityPubkey) external view {
        bytes32 got = helpers.computeG4AuthorityRef(authorityPubkey);
        bytes32 expected = keccak256(abi.encodePacked(Tags.TAG_G4_ATTESTATION_AUTHORITY_V3, authorityPubkey));
        assertEq(got, expected, "G4 authority ref formula drift");
    }

    /// @notice SupersededCommit lookup MUST be deterministic + collision-resistant
    ///         across (ref, generation) tuples.
    function testFuzz_supersededCommitLookup_isCollisionResistant(
        bytes32 ref1,
        uint16 gen1,
        bytes32 ref2,
        uint16 gen2
    ) external view {
        vm.assume(ref1 != ref2 || gen1 != gen2);
        bytes32 a = helpers.computeSupersededCommitLookup(ref1, gen1);
        bytes32 b = helpers.computeSupersededCommitLookup(ref2, gen2);
        assertTrue(a != b, "supersededCommit lookup collision");
    }

    /// @notice Plugin version digest is purely a function of canonicalBinaryHash —
    ///         no hidden state.
    function testFuzz_pluginVersionDigest_isDeterministic(bytes32 canonicalBinaryHash) external view {
        bytes32 a = helpers.computePluginVersionDigest(canonicalBinaryHash);
        bytes32 b = helpers.computePluginVersionDigest(canonicalBinaryHash);
        assertEq(a, b, "plugin version digest not deterministic");
    }

    /// @notice Plugin version digest MUST equal keccak256(TAG_PLUGIN_VERSION_V3 ||
    ///         canonicalBinaryHash) — locks the prefix in.
    function testFuzz_pluginVersionDigest_matchesTagPrefixedHash(bytes32 canonicalBinaryHash) external view {
        bytes32 got = helpers.computePluginVersionDigest(canonicalBinaryHash);
        bytes32 expected = keccak256(abi.encodePacked(Tags.TAG_PLUGIN_VERSION_V3, canonicalBinaryHash));
        assertEq(got, expected, "plugin version digest formula drift");
    }

    /// @notice computeAuthorizationId formula lock — keccak256(TAG_AUTHID_V3 ||
    ///         subjectCommitmentV3 || pdaId || pdaVersion(8B BE) || epoch(8B BE) || nonce)
    ///         per S2-1 §3.2.1.
    function testFuzz_authorizationId_matchesTagPrefixedHash(
        bytes32 subjectCommitmentV3,
        bytes32 pdaId,
        uint64 pdaVersion,
        uint64 epoch,
        bytes32 nonce
    ) external view {
        bytes32 got = helpers.computeAuthorizationId(subjectCommitmentV3, pdaId, pdaVersion, epoch, nonce);
        bytes32 expected =
            keccak256(abi.encodePacked(Tags.TAG_AUTHID_V3, subjectCommitmentV3, pdaId, pdaVersion, epoch, nonce));
        assertEq(got, expected, "authorizationId formula drift");
    }

    /// @notice computeAuthorizationId collision-resistance over all 5 input dimensions.
    function testFuzz_authorizationId_isCollisionResistant(
        bytes32 subj1,
        bytes32 pda1,
        uint64 ver1,
        uint64 epoch1,
        bytes32 nonce1,
        bytes32 subj2,
        bytes32 pda2,
        uint64 ver2,
        uint64 epoch2,
        bytes32 nonce2
    ) external view {
        vm.assume(subj1 != subj2 || pda1 != pda2 || ver1 != ver2 || epoch1 != epoch2 || nonce1 != nonce2);
        bytes32 a = helpers.computeAuthorizationId(subj1, pda1, ver1, epoch1, nonce1);
        bytes32 b = helpers.computeAuthorizationId(subj2, pda2, ver2, epoch2, nonce2);
        assertTrue(a != b, "authorizationId collision across distinct inputs");
    }

    /// @notice computeAuthorizationId determinism — same 5-tuple always yields same output.
    function testFuzz_authorizationId_isDeterministic(
        bytes32 subjectCommitmentV3,
        bytes32 pdaId,
        uint64 pdaVersion,
        uint64 epoch,
        bytes32 nonce
    ) external view {
        bytes32 a = helpers.computeAuthorizationId(subjectCommitmentV3, pdaId, pdaVersion, epoch, nonce);
        bytes32 b = helpers.computeAuthorizationId(subjectCommitmentV3, pdaId, pdaVersion, epoch, nonce);
        assertEq(a, b, "authorizationId not deterministic");
    }

    /// @notice computeHCommit determinism — same 15-input struct always yields same output.
    function testFuzz_hCommit_isDeterministic(
        bytes32 authorizationId,
        bytes32 pdaRoot,
        bytes32 schemaDigest,
        bytes32 ciphertextDigest,
        bytes32 aadDigest
    ) external view {
        HCommitFields memory fields = HCommitFields({
            authorizationId: authorizationId,
            pdaRoot: pdaRoot,
            schemaDigest: schemaDigest,
            ciphertextDigest: ciphertextDigest,
            aadDigest: aadDigest,
            compositeIdentityDigest: bytes32(uint256(1)),
            endpointAttestationDigest: bytes32(uint256(2)),
            retentionWindow: 86400,
            shredAuthorityId: bytes32(uint256(3)),
            recipientsRoot: bytes32(uint256(4)),
            revealChallengeWindow: 3600,
            shredChallengeWindow: 7200,
            g3Choice: 1, // drand
            phase: 1, // G4 Phase 1
            commitVersion: 0x0301
        });
        bytes32 a = helpers.computeHCommit(fields);
        bytes32 b = helpers.computeHCommit(fields);
        assertEq(a, b, "hCommit not deterministic");
    }

    /// @notice computeHCommit collision-resistance over authorizationId axis.
    function testFuzz_hCommit_isCollisionResistantOnAuthorizationId(
        bytes32 authorizationId1,
        bytes32 authorizationId2,
        bytes32 sharedPdaRoot
    ) external view {
        vm.assume(authorizationId1 != authorizationId2);
        HCommitFields memory f1 = _baselineHCommitFields(authorizationId1, sharedPdaRoot);
        HCommitFields memory f2 = _baselineHCommitFields(authorizationId2, sharedPdaRoot);
        bytes32 a = helpers.computeHCommit(f1);
        bytes32 b = helpers.computeHCommit(f2);
        assertTrue(a != b, "hCommit collision on distinct authorizationId");
    }

    /// @notice computeHCommit collision-resistance over commitVersion axis (different
    ///         protocol versions MUST produce different commit hashes).
    function testFuzz_hCommit_isCollisionResistantOnCommitVersion(
        uint16 v1,
        uint16 v2,
        bytes32 authorizationId,
        bytes32 pdaRoot
    ) external view {
        vm.assume(v1 != v2);
        HCommitFields memory f1 = _baselineHCommitFields(authorizationId, pdaRoot);
        f1.commitVersion = v1;
        HCommitFields memory f2 = _baselineHCommitFields(authorizationId, pdaRoot);
        f2.commitVersion = v2;
        bytes32 a = helpers.computeHCommit(f1);
        bytes32 b = helpers.computeHCommit(f2);
        assertTrue(a != b, "hCommit collision across distinct commitVersion");
    }

    /// @dev Baseline 15-field struct with caller-overridable authorizationId/pdaRoot.
    ///      Used by the collision tests to vary one axis at a time.
    function _baselineHCommitFields(bytes32 authorizationId, bytes32 pdaRoot)
        private
        pure
        returns (HCommitFields memory)
    {
        return HCommitFields({
            authorizationId: authorizationId,
            pdaRoot: pdaRoot,
            schemaDigest: bytes32(uint256(0x11)),
            ciphertextDigest: bytes32(uint256(0x22)),
            aadDigest: bytes32(uint256(0x33)),
            compositeIdentityDigest: bytes32(uint256(0x44)),
            endpointAttestationDigest: bytes32(uint256(0x55)),
            retentionWindow: 86400,
            shredAuthorityId: bytes32(uint256(0x66)),
            recipientsRoot: bytes32(uint256(0x77)),
            revealChallengeWindow: 3600,
            shredChallengeWindow: 7200,
            g3Choice: 1,
            phase: 1,
            commitVersion: 0x0301
        });
    }
}
