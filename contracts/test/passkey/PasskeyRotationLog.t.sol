// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { PasskeyRotationLog } from "../../src/passkey/PasskeyRotationLog.sol";
import { Tags } from "../../src/lib/Tags.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract PasskeyRotationLogTest is Test {
    PasskeyRotationLog internal rotationLog;

    address internal timelock = address(0x7001);
    bytes32 internal accountId = keccak256("account");

    function setUp() public {
        rotationLog = PasskeyRotationLog(
            ProxyDeploy.deployProxy(
                address(new PasskeyRotationLog()), abi.encodeCall(PasskeyRotationLog.initialize, (timelock))
            )
        );
    }

    function test_monotonicEntryIndexEnforced() external {
        bytes memory entry =
            _encodedEntry(1, address(rotationLog), new bytes(0), _pubkey(1), new bytes(0), _mlkem(1), hex"01");
        vm.expectRevert(
            abi.encodeWithSelector(
                PasskeyRotationLog.RotationIndexNonmonotonic.selector, accountId, uint32(0), uint32(1)
            )
        );
        rotationLog.appendRotation(accountId, entry, bytes32(0));
    }

    function test_contractAddressMismatchReverts() external {
        bytes memory entry =
            _encodedEntry(0, address(0xDEAD), new bytes(0), _pubkey(1), new bytes(0), _mlkem(1), new bytes(0));
        vm.expectRevert(
            abi.encodeWithSelector(
                PasskeyRotationLog.RotationContractAddressMismatch.selector, address(rotationLog), address(0xDEAD)
            )
        );
        rotationLog.appendRotation(accountId, entry, bytes32(0));
    }

    function test_appendAndRangeRead() external {
        // Index-1 append now requires a prior-passkey P-256 assertion (F-3 fix):
        // valid-prefix pubkeys, a 64-byte raw sig, the §13.3-bound digest, and a
        // RIP-7212 precompile that verifies it. Mock the precompile as valid.
        vm.etch(RIP7212, hex"600160005260206000f3");
        bytes memory pub0 = _validP256Pubkey(1);
        bytes memory pub1 = _validP256Pubkey(2);

        bytes memory entry0 =
            _encodedEntry(0, address(rotationLog), new bytes(0), pub0, new bytes(0), _mlkem(1), new bytes(0));
        rotationLog.appendRotation(accountId, entry0, bytes32(0));

        bytes memory entry1 =
            _encodedEntry(1, address(rotationLog), pub0, pub1, _mlkem(1), _mlkem(2), _rawSig(0x33));
        bytes32 boundDigest = keccak256(
            abi.encode(
                Tags.TAG_ROTATION_AUTHORIZATION_V3,
                address(rotationLog),
                accountId,
                uint32(1),
                pub1,
                _mlkem(2),
                uint64(block.timestamp)
            )
        );
        rotationLog.appendRotation(accountId, entry1, boundDigest);

        assertEq(rotationLog.getHead(accountId), 1);
        bytes[] memory entries = rotationLog.getEntries(accountId, 0, 2);
        assertEq(entries.length, 2);
        assertEq(keccak256(entries[0]), keccak256(entry0));
        assertEq(keccak256(entries[1]), keccak256(entry1));
    }

    function test_getEntriesRangeBoundsChecked() external {
        bytes memory entry0 =
            _encodedEntry(0, address(rotationLog), new bytes(0), _pubkey(1), new bytes(0), _mlkem(1), new bytes(0));
        rotationLog.appendRotation(accountId, entry0, bytes32(0));

        vm.expectRevert(
            abi.encodeWithSelector(PasskeyRotationLog.RotationRangeInvalid.selector, accountId, uint32(0), uint32(2))
        );
        rotationLog.getEntries(accountId, 0, 2);
    }

    function test_computeRotationLogAnchorMatchesAppAFieldSet() external view {
        bytes memory passkey = _pubkey(7);
        bytes memory mlkem = _mlkem(8);
        bytes32 got = rotationLog.computeRotationLogAnchor(address(rotationLog), accountId, 3, passkey, mlkem);
        // Matches impl: abi.encode (length-prefixed) per Slither HIGH
        // encode-packed-collision fix in PasskeyRotationLog.computeRotationLogAnchor.
        bytes32 expected = keccak256(
            abi.encode(
                Tags.TAG_ROTATION_LOG_ANCHOR_V3, address(rotationLog), accountId, uint32(3), passkey, mlkem
            )
        );
        assertEq(got, expected);
    }

    function _encodedEntry(
        uint32 index,
        address contractAddress,
        bytes memory prevPubkey,
        bytes memory newPubkey,
        bytes memory prevMlkem,
        bytes memory newMlkem,
        bytes memory assertion
    ) internal view returns (bytes memory) {
        return abi.encode(
            PasskeyRotationLog.PasskeyRotationEntry({
                prevPubkey: prevPubkey,
                newPubkey: newPubkey,
                timestamp: uint64(block.timestamp),
                webauthnAssertion: assertion,
                prevMlkemPubkey: prevMlkem,
                newMlkemPubkey: newMlkem,
                entryIndex: index,
                contractAddress: contractAddress
            })
        );
    }

    // --------------------------------------------------------------------
    // F-3 — appendRotation prior-passkey P-256 authentication
    // --------------------------------------------------------------------

    address internal constant RIP7212 = 0x0000000000000000000000000000000000000100;

    /// @dev Lands entry 0 so the chain head exists and is publicly readable.
    function _seedEntry0() internal returns (bytes memory pub0) {
        pub0 = _validP256Pubkey(0xAA);
        bytes memory entry0 = _encodedEntry(0, address(rotationLog), new bytes(0), pub0, new bytes(0), _mlkem(1), new bytes(0));
        rotationLog.appendRotation(accountId, entry0, bytes32(0));
    }

    /// @notice F-3 attack path: an attacker who reads the public head appends
    ///         index 1 setting newPubkey to a key they control, prevPubkey to the
    ///         current head's newPubkey, an arbitrary non-empty assertion, and an
    ///         arbitrary non-zero digest. Against the vulnerable code this SUCCEEDED
    ///         (zero signature auth). With the fix it reverts on the digest binding.
    function test_F3_arbitraryDigestRejected() external {
        bytes memory headPub = _seedEntry0();
        bytes memory attackerPub = _validP256Pubkey(0xEE);

        bytes memory hijack =
            _encodedEntry(1, address(rotationLog), headPub, attackerPub, _mlkem(1), _mlkem(2), hex"deadbeef");
        // Attacker supplies an arbitrary non-zero digest — accepted by the old
        // `digest != bytes32(0)` check. Now bound to entry contents, so rejected.
        vm.expectRevert();
        rotationLog.appendRotation(accountId, hijack, keccak256("attacker-chosen-digest"));

        // Head is unchanged: the legitimate chain owner still owns index 1.
        assertEq(rotationLog.getHead(accountId), 0);
    }

    /// @notice F-3 attack path, harder variant: the attacker correctly recomputes
    ///         the §13.3 bound digest (it is a public pure function of public fields),
    ///         passes a non-empty 64-byte assertion, but cannot produce a valid P-256
    ///         signature under the PRIOR passkey. With no RIP-7212 precompile present
    ///         on the local EVM the verifier fails closed → revert. This is the core
    ///         closure: reading the public head does not let the attacker hijack the
    ///         chain, because they cannot forge the prior-passkey assertion.
    function test_F3_boundDigestButForgedSignatureRejected() external {
        bytes memory headPub = _seedEntry0();
        bytes memory attackerPub = _validP256Pubkey(0xEE);

        PasskeyRotationLog.PasskeyRotationEntry memory e = PasskeyRotationLog.PasskeyRotationEntry({
            prevPubkey: headPub,
            newPubkey: attackerPub,
            timestamp: uint64(block.timestamp),
            webauthnAssertion: _rawSig(0x11), // 64 bytes of attacker-chosen r‖s
            prevMlkemPubkey: _mlkem(1),
            newMlkemPubkey: _mlkem(2),
            entryIndex: 1,
            contractAddress: address(rotationLog)
        });
        bytes memory hijack = abi.encode(e);

        // Recompute the exact bound digest the contract will check (public fields).
        bytes32 boundDigest = keccak256(
            abi.encode(
                Tags.TAG_ROTATION_AUTHORIZATION_V3,
                address(rotationLog),
                accountId,
                uint32(1),
                attackerPub,
                _mlkem(2),
                uint64(block.timestamp)
            )
        );

        // Digest binding passes; signature verification fails closed (no precompile).
        vm.expectRevert(
            abi.encodeWithSelector(PasskeyRotationLog.RotationWebAuthnInvalid.selector, accountId, uint32(1))
        );
        rotationLog.appendRotation(accountId, hijack, boundDigest);
        assertEq(rotationLog.getHead(accountId), 0);
    }

    /// @notice Positive path: a rotation whose digest is correctly bound AND whose
    ///         assertion verifies under the prior passkey via a mocked-valid RIP-7212
    ///         precompile is accepted. Confirms the fix does not brick legitimate
    ///         rotations. The mock returns abi.encode(uint256(1)) for any input,
    ///         standing in for a real prior-passkey P-256 signature.
    function test_F3_validPriorPasskeyAssertionAccepted() external {
        bytes memory headPub = _seedEntry0();
        bytes memory nextPub = _validP256Pubkey(0xBB);

        // Mock RIP-7212 as "always valid" (real precompile would verify r‖s under qx,qy).
        vm.etch(RIP7212, hex"600160005260206000f3"); // PUSH1 1; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN

        PasskeyRotationLog.PasskeyRotationEntry memory e = PasskeyRotationLog.PasskeyRotationEntry({
            prevPubkey: headPub,
            newPubkey: nextPub,
            timestamp: uint64(block.timestamp),
            webauthnAssertion: _rawSig(0x22),
            prevMlkemPubkey: _mlkem(1),
            newMlkemPubkey: _mlkem(2),
            entryIndex: 1,
            contractAddress: address(rotationLog)
        });
        bytes memory entry1 = abi.encode(e);
        bytes32 boundDigest = keccak256(
            abi.encode(
                Tags.TAG_ROTATION_AUTHORIZATION_V3,
                address(rotationLog),
                accountId,
                uint32(1),
                nextPub,
                _mlkem(2),
                uint64(block.timestamp)
            )
        );

        rotationLog.appendRotation(accountId, entry1, boundDigest);
        assertEq(rotationLog.getHead(accountId), 1);
        bytes memory stored = rotationLog.getEntry(accountId, 1);
        assertEq(keccak256(stored), keccak256(entry1));
    }

    /// @notice Even with the valid-precompile mock, a wrong-length assertion (not the
    ///         raw 64-byte r‖s) fails closed — forecloses the old "any non-empty
    ///         assertion" path that F-3 relied on.
    function test_F3_wrongLengthAssertionRejected() external {
        bytes memory headPub = _seedEntry0();
        bytes memory nextPub = _validP256Pubkey(0xBB);
        vm.etch(RIP7212, hex"600160005260206000f3");

        PasskeyRotationLog.PasskeyRotationEntry memory e = PasskeyRotationLog.PasskeyRotationEntry({
            prevPubkey: headPub,
            newPubkey: nextPub,
            timestamp: uint64(block.timestamp),
            webauthnAssertion: hex"abcd", // 2 bytes, not the raw 64-byte P-256 sig
            prevMlkemPubkey: _mlkem(1),
            newMlkemPubkey: _mlkem(2),
            entryIndex: 1,
            contractAddress: address(rotationLog)
        });
        bytes memory entry1 = abi.encode(e);
        bytes32 boundDigest = keccak256(
            abi.encode(
                Tags.TAG_ROTATION_AUTHORIZATION_V3,
                address(rotationLog),
                accountId,
                uint32(1),
                nextPub,
                _mlkem(2),
                uint64(block.timestamp)
            )
        );
        vm.expectRevert(
            abi.encodeWithSelector(PasskeyRotationLog.RotationWebAuthnInvalid.selector, accountId, uint32(1))
        );
        rotationLog.appendRotation(accountId, entry1, boundDigest);
        assertEq(rotationLog.getHead(accountId), 0);
    }

    /// @dev 65-byte uncompressed P-256 pubkey 0x04 ‖ x ‖ y (non-zero body).
    function _validP256Pubkey(uint8 seed) internal pure returns (bytes memory out) {
        out = new bytes(65);
        out[0] = 0x04;
        for (uint256 i = 1; i < out.length; ++i) {
            out[i] = bytes1(seed);
        }
    }

    /// @dev 64-byte raw P-256 signature r ‖ s.
    function _rawSig(uint8 seed) internal pure returns (bytes memory out) {
        out = new bytes(64);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = bytes1(seed);
        }
    }

    function _pubkey(uint8 seed) internal pure returns (bytes memory out) {
        out = new bytes(65);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = bytes1(seed);
        }
    }

    function _mlkem(uint8 seed) internal pure returns (bytes memory out) {
        out = new bytes(1184);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = bytes1(seed);
        }
    }
}
