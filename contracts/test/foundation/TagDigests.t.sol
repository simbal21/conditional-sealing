// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { Tags } from "../../src/lib/Tags.sol";

/// @title TagDigests.t - load-bearing TAG_*_V3 anti-drift gate
/// @notice Loads `../v3-crypto/test/fixtures/tag-digests.golden.json` and asserts
///         (a) `keccak256(bytes(LABEL)) == DIGEST` for each of 30 entries, and
///         (b) the Solidity constant in `Tags.sol` equals the digest.
///
/// @dev Per internal solidity rules (not exported) §1 universal: drift in any TAG_*_V3
///      hex digest breaks every TAG-prefixed lookup across the 4-gate stack.
///      This test is the trip-wire that prevents silent drift.
contract TagDigestsTest is Test {
    /// @notice Path resolves under `foundry.toml` `fs_permissions` for `./`.
    string internal constant FIXTURE_PATH = "../v3-crypto/test/fixtures/tag-digests.golden.json";

    /// @notice Driver test: parse the golden fixture, assert all 30 keccak rules,
    ///         and assert all 30 Solidity constants match.
    function test_TagDigests_All30LabelsHashToDigests_AndConstantsMatch() external {
        string memory json = vm.readFile(FIXTURE_PATH);

        // Decode the fixture's `tags` array. Each entry is {symbol, label, digest}.
        // Use length+iteration access via vm.parseJson + per-key accessors.
        bytes memory metaCountBytes = vm.parseJson(json, "._meta.count");
        uint256 declaredCount = abi.decode(metaCountBytes, (uint256));
        assertEq(declaredCount, 30, "fixture _meta.count must be 30");

        // Iterate each tag entry by index.
        for (uint256 i = 0; i < declaredCount; i++) {
            string memory keyBase = string.concat(".tags[", vm.toString(i), "]");
            string memory symbol = abi.decode(vm.parseJson(json, string.concat(keyBase, ".symbol")), (string));
            string memory label = abi.decode(vm.parseJson(json, string.concat(keyBase, ".label")), (string));
            bytes32 digest = abi.decode(vm.parseJson(json, string.concat(keyBase, ".digest")), (bytes32));

            // Rule (a): keccak256(bytes(LABEL)) must equal DIGEST.
            bytes32 computed = keccak256(bytes(label));
            assertEq(computed, digest, string.concat("keccak(label) mismatch for ", symbol));

            // Rule (b): the corresponding Solidity constant in Tags.sol must equal DIGEST.
            bytes32 fromConstant = _tagBySymbol(symbol);
            assertEq(fromConstant, digest, string.concat("Tags.sol constant mismatch for ", symbol));
        }
    }

    /// @notice Per-tag spot-checks against the locked M1 hex (defense-in-depth
    ///         against a corrupted fixture file).
    function test_TagDigests_SpotChecks_KnownConstantsMatchM1Hex() external pure {
        assertEq(
            Tags.TAG_COMMIT_V3,
            bytes32(0x2d2217e4d967ed248e767e28fbd079ef83164a25c8cbcf94387c115336726615),
            "TAG_COMMIT_V3"
        );
        assertEq(
            Tags.TAG_AUTHID_V3,
            bytes32(0x2515365985f25edab9af1617075766433983edd0fd267b0a8a55d37e7d838890),
            "TAG_AUTHID_V3"
        );
        assertEq(
            Tags.TAG_SUBJECT_V3,
            bytes32(0x7a3cd7f29faeb061b53c59ce8eecfa833ecf1cbf49300f3a7c3302b29affc667),
            "TAG_SUBJECT_V3"
        );
        assertEq(
            Tags.TAG_PDA_ROOT_V3,
            bytes32(0x2e9aef6890ee90a57f6cbc9f7301799f914fe95b03dd711065ebf5b8b3fa31ec),
            "TAG_PDA_ROOT_V3"
        );
        assertEq(
            Tags.TAG_AAD_V3, bytes32(0x5f09deb22a5104e36edaa6ab19e7de91e965cd565b2b1ad45da57eaa2aae9072), "TAG_AAD_V3"
        );
        assertEq(
            Tags.TAG_SUPERSEDED_COMMIT_REGISTRY_V3,
            bytes32(0xc9c3c0c6dd22412a9da1c864e5ea8144ee9c791543522c5da49ea0f14c70732e),
            "TAG_SUPERSEDED_COMMIT_REGISTRY_V3"
        );
        assertEq(
            Tags.TAG_ORACLE_REGISTRY_V3,
            bytes32(0x5fd88bdfc47cbf2f7b151337f5ee0f4bf08a20394311a0d85e60f921e2b36010),
            "TAG_ORACLE_REGISTRY_V3"
        );
    }

    /// @dev Map symbol-string -> Tags.sol constant value. Updates here when
    ///      a TAG is added/removed (per S2-1 §2.8 commit_version bump rule).
    function _tagBySymbol(string memory symbol) internal pure returns (bytes32) {
        bytes32 sh = keccak256(bytes(symbol));
        if (sh == keccak256(bytes("TAG_COMMIT_V3"))) return Tags.TAG_COMMIT_V3;
        if (sh == keccak256(bytes("TAG_AUTHID_V3"))) return Tags.TAG_AUTHID_V3;
        if (sh == keccak256(bytes("TAG_SUBJECT_V3"))) return Tags.TAG_SUBJECT_V3;
        if (sh == keccak256(bytes("TAG_SIGMA_SUBJECT_V3"))) return Tags.TAG_SIGMA_SUBJECT_V3;
        if (sh == keccak256(bytes("TAG_PDA_ROOT_V3"))) return Tags.TAG_PDA_ROOT_V3;
        if (sh == keccak256(bytes("TAG_AAD_V3"))) return Tags.TAG_AAD_V3;
        if (sh == keccak256(bytes("TAG_AEAD_V3"))) return Tags.TAG_AEAD_V3;
        if (sh == keccak256(bytes("TAG_COMMIT_CONTEXT_V3"))) return Tags.TAG_COMMIT_CONTEXT_V3;
        if (sh == keccak256(bytes("TAG_ATTESTATION_CONTEXT_V3"))) return Tags.TAG_ATTESTATION_CONTEXT_V3;
        if (sh == keccak256(bytes("TAG_LIT_ACC_BINDING_V3"))) return Tags.TAG_LIT_ACC_BINDING_V3;
        if (sh == keccak256(bytes("TAG_DCIPHER_IBE_BINDING_V3"))) return Tags.TAG_DCIPHER_IBE_BINDING_V3;
        if (sh == keccak256(bytes("TAG_DRAND_ROUND_BINDING_V3"))) return Tags.TAG_DRAND_ROUND_BINDING_V3;
        if (sh == keccak256(bytes("TAG_G3_BINDING_V3"))) return Tags.TAG_G3_BINDING_V3;
        if (sh == keccak256(bytes("TAG_G4_ATTESTATION_V3"))) return Tags.TAG_G4_ATTESTATION_V3;
        if (sh == keccak256(bytes("TAG_G4_ATTESTATION_AUTHORITY_V3"))) {
            return Tags.TAG_G4_ATTESTATION_AUTHORITY_V3;
        }
        if (sh == keccak256(bytes("TAG_COMPOSITE_IDENTITY_V3"))) return Tags.TAG_COMPOSITE_IDENTITY_V3;
        if (sh == keccak256(bytes("TAG_STANZA_MAC_V3"))) return Tags.TAG_STANZA_MAC_V3;
        if (sh == keccak256(bytes("TAG_STANZA_WRAP_V3"))) return Tags.TAG_STANZA_WRAP_V3;
        if (sh == keccak256(bytes("TAG_STANZA_WRAP_NONCE_V3"))) return Tags.TAG_STANZA_WRAP_NONCE_V3;
        if (sh == keccak256(bytes("TAG_CONDITIONAL_RECIPIENT_BINDING_V3"))) {
            return Tags.TAG_CONDITIONAL_RECIPIENT_BINDING_V3;
        }
        if (sh == keccak256(bytes("TAG_REVEAL_CHALLENGE_V3"))) return Tags.TAG_REVEAL_CHALLENGE_V3;
        if (sh == keccak256(bytes("TAG_RECIPIENT_LEAF_V3"))) return Tags.TAG_RECIPIENT_LEAF_V3;
        if (sh == keccak256(bytes("TAG_P15_ATTESTATION_V3"))) return Tags.TAG_P15_ATTESTATION_V3;
        if (sh == keccak256(bytes("TAG_ARTIFACT_V3"))) return Tags.TAG_ARTIFACT_V3;
        if (sh == keccak256(bytes("TAG_PLUGIN_VERSION_V3"))) return Tags.TAG_PLUGIN_VERSION_V3;
        if (sh == keccak256(bytes("TAG_ROTATION_LOG_ANCHOR_V3"))) return Tags.TAG_ROTATION_LOG_ANCHOR_V3;
        if (sh == keccak256(bytes("TAG_CONDITIONAL_RECIPIENTS_POLICY_V3"))) {
            return Tags.TAG_CONDITIONAL_RECIPIENTS_POLICY_V3;
        }
        if (sh == keccak256(bytes("TAG_SUPERSEDED_COMMIT_REGISTRY_V3"))) {
            return Tags.TAG_SUPERSEDED_COMMIT_REGISTRY_V3;
        }
        if (sh == keccak256(bytes("TAG_ROTATION_AUTHORIZATION_V3"))) return Tags.TAG_ROTATION_AUTHORIZATION_V3;
        if (sh == keccak256(bytes("TAG_ORACLE_REGISTRY_V3"))) return Tags.TAG_ORACLE_REGISTRY_V3;
        revert(string.concat("unknown tag symbol in fixture: ", symbol));
    }
}
