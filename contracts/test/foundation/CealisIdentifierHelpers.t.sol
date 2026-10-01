// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { CealisIdentifierHelpers } from "../../src/helpers/CealisIdentifierHelpers.sol";
import { Tags } from "../../src/lib/Tags.sol";
import { PdaRootFields, HCommitFields } from "../../src/lib/Structs.sol";

/// @title CealisIdentifierHelpers.t - byte-exact differential test against M1
/// @notice Load-bearing test for Phase A. Asserts the on-chain helpers
///         produce byte-identical output to the M1 TS reference at
///         `v3-crypto/src/codecs/pda-root.ts` for the LOCKED
///         `all_zero` and `canonical_fixture_v1` vectors.
///
///         For helpers without an M1 TS counterpart (subject_commitment_v3,
///         authorizationId, plugin_version_digest, g4_authority_ref,
///         superseded_commit_lookup), this test re-derives the expected
///         digest from the S2-1 spec construction and asserts the helper's
///         keccak input matches.
///
/// @dev If a vector mismatches, DO NOT mutate either side - HALT and surface
///      the contradiction per the Phase A failure-mode rules.
contract CealisIdentifierHelpersTest is Test {
    CealisIdentifierHelpers internal helpers;

    string internal constant PDA_ROOT_FIXTURE = "../v3-crypto/test/fixtures/pda-root.golden.json";

    function setUp() public {
        helpers = new CealisIdentifierHelpers();
    }

    // ---------------------------------------------------------------------
    // pda_root - DIFFERENTIAL against M1 golden fixtures
    // ---------------------------------------------------------------------

    function test_computePdaRoot_AllZeroVector_MatchesM1() external {
        PdaRootFields memory fields = _zeroPdaRootFields();
        bytes32 got = helpers.computePdaRoot(fields);

        // Vector 1 expected pda_root from
        // ../v3-crypto/test/fixtures/pda-root.golden.json
        bytes32 expected = bytes32(0xf42e5b895a5e57bf91e0bed824843ffc31c7838894b009866fb1be2e4fd8ea25);
        assertEq(got, expected, "all_zero pda_root must match M1 golden vector");
    }

    function test_computePdaRoot_CanonicalFixtureV1_MatchesM1() external {
        // Per fixture description, byte i of field_index N = ((N+1)*(i+1)) & 0xff,
        // BUT the canonical fixture overrides several fields per the per-field rules:
        //   - art_9_scoped = false      => art_9_basis_id zero
        //   - legal_effect_expected=true => cealis_class_wide_halt_opt_out = false
        //   - subject_authenticator_class = 1 (platform_authenticator)
        //   - Mode-P-only => wasm_predicate_hashes_root + submitter_sets_root zeroed
        //   - minimum_shred_latency = 86400 (1 day)
        //
        // We don't recompute the per-field deterministic fill here - we read the
        // expected `pda_root` from the fixture and compare to a Solidity-built
        // input that we *parse from the fixture's preimage_hex* slice-by-slice.
        // That keeps this test honest: even a brief-vs-fixture order mismatch
        // would be caught.

        string memory json = vm.readFile(PDA_ROOT_FIXTURE);
        bytes memory preimage = abi.decode(vm.parseJson(json, ".vectors[1].preimage_hex"), (bytes));
        bytes32 expected = abi.decode(vm.parseJson(json, ".vectors[1].pda_root"), (bytes32));

        // Sanity: preimage must be 540 bytes, first 32 bytes = TAG_PDA_ROOT_V3.
        assertEq(preimage.length, 540, "preimage must be 540 bytes");
        bytes32 firstTag;
        assembly {
            firstTag := mload(add(preimage, 32))
        }
        assertEq(firstTag, Tags.TAG_PDA_ROOT_V3, "preimage prefix must be TAG_PDA_ROOT_V3");
        assertEq(keccak256(preimage), expected, "fixture self-consistency: keccak(preimage) == expected pda_root");

        // Now build the same input via our struct + helper and compare.
        PdaRootFields memory fields = _parsePdaRootFromPreimage(preimage);
        bytes32 got = helpers.computePdaRoot(fields);
        assertEq(got, expected, "canonical_fixture_v1 pda_root must match M1 golden vector");
    }

    // ---------------------------------------------------------------------
    // h_commit - SELF-CONSISTENCY (no M1 TS counterpart)
    // ---------------------------------------------------------------------

    function test_computeHCommit_AllZeroVector_MatchesSpecConstruction() external {
        HCommitFields memory fields = _zeroHCommitFields();
        bytes32 got = helpers.computeHCommit(fields);

        // S2-1 §3.4.1 preimage = 32 (TAG) + 9*32 + 8 + 4 + 4 + 1 + 1 + 2 = 340 bytes.
        // For all-zero inputs, the expected = keccak256(TAG_COMMIT_V3 ‖ 308 zero bytes).
        bytes memory expectedPreimage = abi.encodePacked(
            Tags.TAG_COMMIT_V3,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            uint64(0),
            bytes32(0),
            bytes32(0),
            uint32(0),
            uint32(0),
            uint8(0),
            uint8(0),
            uint16(0)
        );
        assertEq(expectedPreimage.length, 340, "h_commit preimage must be 340 bytes");
        bytes32 expected = keccak256(expectedPreimage);
        assertEq(got, expected, "all-zero h_commit matches spec construction");
    }

    function test_computeHCommit_CanonicalVector_MatchesSpecConstruction() external {
        // Use deterministic per-field bytes to build a non-trivial vector and
        // compare against direct keccak of an abi.encodePacked recomputation.
        HCommitFields memory fields = HCommitFields({
            authorizationId: bytes32(uint256(0x01) << 248),
            pdaRoot: bytes32(uint256(0x02) << 248),
            schemaDigest: bytes32(uint256(0x03) << 248),
            ciphertextDigest: bytes32(uint256(0x04) << 248),
            aadDigest: bytes32(uint256(0x05) << 248),
            compositeIdentityDigest: bytes32(uint256(0x06) << 248),
            endpointAttestationDigest: bytes32(uint256(0x07) << 248),
            retentionWindow: 86_400,
            shredAuthorityId: bytes32(uint256(0x08) << 248),
            recipientsRoot: bytes32(uint256(0x09) << 248),
            revealChallengeWindow: 3600,
            shredChallengeWindow: 7200,
            g3Choice: 0,
            phase: 2,
            commitVersion: 0x0302
        });
        bytes32 got = helpers.computeHCommit(fields);
        bytes memory expectedPreimage = abi.encodePacked(
            Tags.TAG_COMMIT_V3,
            fields.authorizationId,
            fields.pdaRoot,
            fields.schemaDigest,
            fields.ciphertextDigest,
            fields.aadDigest,
            fields.compositeIdentityDigest,
            fields.endpointAttestationDigest,
            fields.retentionWindow,
            fields.shredAuthorityId,
            fields.recipientsRoot,
            fields.revealChallengeWindow,
            fields.shredChallengeWindow,
            fields.g3Choice,
            fields.phase,
            fields.commitVersion
        );
        assertEq(expectedPreimage.length, 340, "preimage 340 bytes");
        assertEq(got, keccak256(expectedPreimage), "h_commit byte-equivalence");
    }

    // ---------------------------------------------------------------------
    // subject_commitment_v3 - per S2-1 §3.1.1
    // ---------------------------------------------------------------------

    function test_computeSubjectCommitmentV3_PreimageLayoutPerSpec() external view {
        bytes32 personKey = bytes32(uint256(1));
        bytes32 partnerNamespace = bytes32(uint256(2));
        bytes32 registrationNonce = bytes32(uint256(3));
        bytes32 got = helpers.computeSubjectCommitmentV3(personKey, partnerNamespace, registrationNonce);
        bytes memory preimage = abi.encodePacked(Tags.TAG_SUBJECT_V3, personKey, partnerNamespace, registrationNonce);
        assertEq(preimage.length, 128, "preimage 128 bytes");
        assertEq(got, keccak256(preimage), "subject_commitment_v3 byte-equivalence");
    }

    function test_computeSubjectCommitmentV3_AllZero() external view {
        bytes32 got = helpers.computeSubjectCommitmentV3(bytes32(0), bytes32(0), bytes32(0));
        bytes memory preimage = abi.encodePacked(Tags.TAG_SUBJECT_V3, bytes32(0), bytes32(0), bytes32(0));
        assertEq(got, keccak256(preimage));
    }

    // ---------------------------------------------------------------------
    // authorizationId - per S2-1 §3.2.1
    // ---------------------------------------------------------------------

    function test_computeAuthorizationId_PreimageLayoutPerSpec() external view {
        bytes32 subjectCommitmentV3 = bytes32(uint256(0xAA) << 248);
        bytes32 pdaId = bytes32(uint256(0xBB) << 248);
        uint64 pdaVersion = 1;
        uint64 epoch = 1_700_000_000;
        bytes32 nonce = bytes32(uint256(0xCC) << 248);
        bytes32 got = helpers.computeAuthorizationId(subjectCommitmentV3, pdaId, pdaVersion, epoch, nonce);
        bytes memory preimage =
            abi.encodePacked(Tags.TAG_AUTHID_V3, subjectCommitmentV3, pdaId, pdaVersion, epoch, nonce);
        assertEq(preimage.length, 144, "preimage 144 bytes");
        assertEq(got, keccak256(preimage), "authorizationId byte-equivalence");
    }

    // ---------------------------------------------------------------------
    // plugin_version_digest - per S2-1 §2.3.4
    // ---------------------------------------------------------------------

    function test_computePluginVersionDigest_PreimageLayoutPerSpec() external view {
        bytes32 hash = bytes32(uint256(0xDEADBEEF));
        bytes32 got = helpers.computePluginVersionDigest(hash);
        bytes memory preimage = abi.encodePacked(Tags.TAG_PLUGIN_VERSION_V3, hash);
        assertEq(preimage.length, 64);
        assertEq(got, keccak256(preimage));
    }

    // ---------------------------------------------------------------------
    // g4_authority_ref - per S2-1 §2.3.3
    // ---------------------------------------------------------------------

    function test_computeG4AuthorityRef_VariableLengthBytes() external view {
        bytes memory pubkey = hex"01020304050607";
        bytes32 got = helpers.computeG4AuthorityRef(pubkey);
        bytes memory preimage = abi.encodePacked(Tags.TAG_G4_ATTESTATION_AUTHORITY_V3, pubkey);
        assertEq(preimage.length, 32 + 7);
        assertEq(got, keccak256(preimage));
    }

    function test_computeG4AuthorityRef_EmptyBytes() external view {
        bytes memory pubkey;
        bytes32 got = helpers.computeG4AuthorityRef(pubkey);
        bytes32 expected = keccak256(abi.encodePacked(Tags.TAG_G4_ATTESTATION_AUTHORITY_V3));
        assertEq(got, expected);
    }

    // ---------------------------------------------------------------------
    // superseded_commit_lookup - per S2-1 §15.6.3
    // ---------------------------------------------------------------------

    function test_computeSupersededCommitLookup_PreimageLayoutPerSpec() external view {
        bytes32 ref = bytes32(uint256(0x1234));
        uint16 generation = 7;
        bytes32 got = helpers.computeSupersededCommitLookup(ref, generation);
        bytes memory preimage = abi.encodePacked(Tags.TAG_SUPERSEDED_COMMIT_REGISTRY_V3, ref, generation);
        assertEq(preimage.length, 32 + 32 + 2);
        assertEq(got, keccak256(preimage));
    }

    function test_computeSupersededCommitLookup_BigEndianGeneration() external view {
        // generation 0x0102 should encode as bytes 01 02 (big-endian).
        bytes32 ref = bytes32(0);
        uint16 generation = 0x0102;
        bytes32 got = helpers.computeSupersededCommitLookup(ref, generation);
        bytes memory preimage = abi.encodePacked(Tags.TAG_SUPERSEDED_COMMIT_REGISTRY_V3, ref, hex"0102");
        assertEq(got, keccak256(preimage), "uint16 must be BE 01 02");
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    function _zeroPdaRootFields() internal pure returns (PdaRootFields memory) {
        return PdaRootFields({
            pdaId: bytes32(0),
            pdaVersion: 0,
            revealConditionMode: 0,
            revealConditionSpecHash: bytes32(0),
            shredConditionMode: 0,
            shredConditionSpecHash: bytes32(0),
            oracleReferencesRoot: bytes32(0),
            dslVersion: bytes32(0),
            wasmPredicateHashesRoot: bytes32(0),
            submitterSetsRoot: bytes32(0),
            pauseAuthorityId: bytes32(0),
            ceremonyResolverId: bytes32(0),
            eligibleChallengersRevealRoot: bytes32(0),
            eligibleChallengersShredRoot: bytes32(0),
            templateId: bytes32(0),
            partnerId: bytes32(0),
            subjectAuthenticatorClass: 0,
            qtspProviderRef: bytes32(0),
            art9Scoped: false,
            art9BasisId: 0,
            legalEffectExpected: false,
            cealisClassWideHaltOptOut: false,
            minimumShredLatency: 0,
            applicableJurisdiction: bytes32(0),
            conditionalRecipientsUpdatable: false,
            subjectLivenessRequiredAtFire: false,
            emergencyResponseBrickingAcknowledgment: false,
            timeCriticalPdaFlag: false,
            pdaUpdatable: false
        });
    }

    function _zeroHCommitFields() internal pure returns (HCommitFields memory) {
        return HCommitFields({
            authorizationId: bytes32(0),
            pdaRoot: bytes32(0),
            schemaDigest: bytes32(0),
            ciphertextDigest: bytes32(0),
            aadDigest: bytes32(0),
            compositeIdentityDigest: bytes32(0),
            endpointAttestationDigest: bytes32(0),
            retentionWindow: 0,
            shredAuthorityId: bytes32(0),
            recipientsRoot: bytes32(0),
            revealChallengeWindow: 0,
            shredChallengeWindow: 0,
            g3Choice: 0,
            phase: 0,
            commitVersion: 0
        });
    }

    /// @dev Parse the canonical 540-byte pda_root preimage back into a
    ///      `PdaRootFields` struct using the M1 byte layout. Byte offsets
    ///      mirror `v3-crypto/src/codecs/pda-root.ts`
    ///      buildPDARootPreimage().
    function _parsePdaRootFromPreimage(bytes memory preimage) internal pure returns (PdaRootFields memory fields) {
        require(preimage.length == 540, "preimage must be 540 bytes");
        // Skip 32 byte TAG prefix.
        uint256 off = 32;

        fields.pdaId = _read32(preimage, off);
        off += 32;
        fields.pdaVersion = _readU64BE(preimage, off);
        off += 8;
        fields.revealConditionMode = uint8(preimage[off]);
        off += 1;
        fields.revealConditionSpecHash = _read32(preimage, off);
        off += 32;
        fields.shredConditionMode = uint8(preimage[off]);
        off += 1;
        fields.shredConditionSpecHash = _read32(preimage, off);
        off += 32;
        fields.oracleReferencesRoot = _read32(preimage, off);
        off += 32;
        fields.dslVersion = _read32(preimage, off);
        off += 32;
        fields.wasmPredicateHashesRoot = _read32(preimage, off);
        off += 32;
        fields.submitterSetsRoot = _read32(preimage, off);
        off += 32;
        fields.pauseAuthorityId = _read32(preimage, off);
        off += 32;
        fields.ceremonyResolverId = _read32(preimage, off);
        off += 32;
        fields.eligibleChallengersRevealRoot = _read32(preimage, off);
        off += 32;
        fields.eligibleChallengersShredRoot = _read32(preimage, off);
        off += 32;
        fields.templateId = _read32(preimage, off);
        off += 32;
        fields.partnerId = _read32(preimage, off);
        off += 32;

        fields.subjectAuthenticatorClass = uint8(preimage[off]);
        off += 1;
        fields.qtspProviderRef = _read32(preimage, off);
        off += 32;
        fields.art9Scoped = preimage[off] != 0;
        off += 1;
        fields.art9BasisId = uint8(preimage[off]);
        off += 1;
        fields.legalEffectExpected = preimage[off] != 0;
        off += 1;
        fields.cealisClassWideHaltOptOut = preimage[off] != 0;
        off += 1;
        fields.minimumShredLatency = _readU64BE(preimage, off);
        off += 8;
        fields.applicableJurisdiction = _read32(preimage, off);
        off += 32;
        fields.conditionalRecipientsUpdatable = preimage[off] != 0;
        off += 1;
        fields.subjectLivenessRequiredAtFire = preimage[off] != 0;
        off += 1;
        fields.emergencyResponseBrickingAcknowledgment = preimage[off] != 0;
        off += 1;
        fields.timeCriticalPdaFlag = preimage[off] != 0;
        off += 1;
        fields.pdaUpdatable = preimage[off] != 0;
        off += 1;

        require(off == 540, "parser: did not consume 540 bytes");
    }

    function _read32(bytes memory b, uint256 off) internal pure returns (bytes32 out) {
        require(off + 32 <= b.length, "_read32 oob");
        assembly {
            out := mload(add(add(b, 32), off))
        }
    }

    function _readU64BE(bytes memory b, uint256 off) internal pure returns (uint64 out) {
        require(off + 8 <= b.length, "_readU64BE oob");
        for (uint256 i = 0; i < 8; i++) {
            out = (out << 8) | uint64(uint8(b[off + i]));
        }
    }
}
