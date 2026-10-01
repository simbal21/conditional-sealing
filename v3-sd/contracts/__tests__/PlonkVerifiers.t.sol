// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";

import { ISdPlonkVerifier } from "../IPlonkVerifier.sol";
import { PlonkVerifierEquality } from "../PlonkVerifierEquality.sol";
import { PlonkVerifierNonEquality } from "../PlonkVerifierNonEquality.sol";
import { PlonkVerifierRange } from "../PlonkVerifierRange.sol";
import { PlonkVerifierSetMembership } from "../PlonkVerifierSetMembership.sol";

contract PlonkVerifiersTest is Test {
    function test_allVerifiersExposeSdPlonkShapeAndRejectMalformedProofs() external {
        uint256[] memory publicInputs = new uint256[](14);

        assertFalse(ISdPlonkVerifier(address(new PlonkVerifierEquality())).verifyProof(hex"01", publicInputs));
        assertFalse(ISdPlonkVerifier(address(new PlonkVerifierNonEquality())).verifyProof(hex"01", publicInputs));
        assertFalse(ISdPlonkVerifier(address(new PlonkVerifierRange())).verifyProof(hex"01", publicInputs));
        assertFalse(ISdPlonkVerifier(address(new PlonkVerifierSetMembership())).verifyProof(hex"01", publicInputs));
    }

    function test_allVerifiersRejectWrongPublicInputCount() external {
        bytes memory proof = new bytes(768);
        uint256[] memory publicInputs = new uint256[](13);

        assertFalse(ISdPlonkVerifier(address(new PlonkVerifierEquality())).verifyProof(proof, publicInputs));
        assertFalse(ISdPlonkVerifier(address(new PlonkVerifierNonEquality())).verifyProof(proof, publicInputs));
        assertFalse(ISdPlonkVerifier(address(new PlonkVerifierRange())).verifyProof(proof, publicInputs));
        assertFalse(ISdPlonkVerifier(address(new PlonkVerifierSetMembership())).verifyProof(proof, publicInputs));
    }
}
