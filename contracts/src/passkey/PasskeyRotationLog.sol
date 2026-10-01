// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";
import { Tags } from "../lib/Tags.sol";

/// @title PasskeyRotationLog - per-account WebAuthn + ML-KEM rotation chain
/// @notice Append-only log of subject passkey rotations. Each subject's chain
///         pins {prevPubkey, newPubkey, webauthnAssertion, prevMlkemPubkey,
///         newMlkemPubkey} per rotation, forming a hash chain anchored to a
///         specific deployment via contractAddress. Used by combiners +
///         G4 verifier to prove a subject's currently-active passkey at
///         commit_block.
/// @dev Permissionless writes (the integrity check is INTERNAL): anyone can
///      call appendRotation, but the entry MUST (a) increment entryIndex
///      monotonically, (b) match this contract's address, (c) carry valid
///      P-256 (65 bytes) + ML-KEM-768 (1184 bytes) pubkey lengths, (d) chain
///      against the prior entry's newPubkey + newMlkemPubkey for index>0,
///      (e) carry a non-empty webauthnAssertion + non-zero rotationAuthorizationDigest
///      for index>0. The first entry (index=0) MUST have empty prev fields
///      (no chain anchor). MAX_PAGE_SIZE=64 caps paginated reads (DoS bound).
///      Anti-collision: computeRotationLogAnchor uses abi.encode (length-prefixed)
///      per Task#13 Slither HIGH fix to prevent multi-dynamic-arg collisions.
contract PasskeyRotationLog is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable {
    struct PasskeyRotationEntry {
        bytes prevPubkey;
        bytes newPubkey;
        uint64 timestamp;
        bytes webauthnAssertion;
        bytes prevMlkemPubkey;
        bytes newMlkemPubkey;
        uint32 entryIndex;
        address contractAddress;
    }

    error RotationAccountUnknown(bytes32 accountId);
    error RotationIndexNonmonotonic(bytes32 accountId, uint32 expected, uint32 actual);
    error RotationPasskeyChainBroken(bytes32 accountId);
    error RotationMlkemChainBroken(bytes32 accountId);
    error RotationWebAuthnInvalid(bytes32 accountId, uint32 entryIndex);
    error RotationAuthorizationDigestMismatch(bytes32 accountId, bytes32 expected, bytes32 actual);
    error RotationContractAddressMismatch(address expected, address actual);
    error RotationRangeInvalid(bytes32 accountId, uint32 fromInclusive, uint32 toExclusive);
    error RotationPaused(bytes32 scope);

    event PasskeyRotationAppended(bytes32 indexed accountId, uint32 indexed entryIndex, bytes32 entryDigest);

    uint256 internal constant P256_PUBKEY_LENGTH = 65;
    uint256 internal constant MLKEM_768_PUBKEY_LENGTH = 1184;
    uint256 internal constant MAX_PAGE_SIZE = 64;
    /// @dev RIP-7212 P-256 (secp256r1) signature-verification precompile on Base.
    ///      Input 160 bytes = msgHash[32] ‖ r[32] ‖ s[32] ‖ qx[32] ‖ qy[32];
    ///      success output = 32-byte word == 1. A missing precompile returns empty
    ///      data (no revert), which this contract treats as verification-FAILED
    ///      (fail-closed) — a rotation that cannot be P-256-authenticated on-chain
    ///      is rejected, never silently accepted.
    address internal constant RIP7212_P256_VERIFY = 0x0000000000000000000000000000000000000100;
    /// @dev WebAuthn raw P-256 ECDSA signature = r ‖ s, exactly 64 bytes
    ///      (S2-1 §1.1.3 / §13.3). The on-chain authentication surface verifies the
    ///      raw r‖s value over the rotation_authorization_digest; full WebAuthn
    ///      framing (clientDataJSON / authenticatorData) is re-validated off-chain
    ///      per S2-2 §10 (DESIGN-SENSITIVE — see appendRotation NatSpec).
    uint256 internal constant P256_RAW_SIG_LENGTH = 64;

    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;
    bytes32 public constant PAUSER_ROLE = Roles.PAUSER_ROLE;
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    mapping(bytes32 => uint32) private _heads;
    mapping(bytes32 => mapping(uint32 => bytes)) private _entries;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
    }

    /// @notice Appends a passkey rotation entry to the per-account chain.
    /// @dev Permissionless by design, but NOT unauthenticated: for entry_index ≥ 1
    ///      the rotation is accepted ONLY if the caller proves possession of the
    ///      PREVIOUS active passkey. The check has three parts: (a) the supplied
    ///      `rotationAuthorizationDigest` MUST equal the §13.3 digest recomputed over
    ///      THIS entry's bound fields (so a caller cannot pass an arbitrary digest);
    ///      (b) `webauthnAssertion` MUST carry a raw 64-byte P-256 ECDSA signature
    ///      (r‖s); (c) that signature MUST verify under `prev.newPubkey` over the
    ///      recomputed digest via the RIP-7212 P-256 precompile (fail-closed if the
    ///      precompile is absent — an unverifiable rotation is rejected, never
    ///      silently accepted). This closes the F-3 chain-hijack: reading the public
    ///      head no longer lets an attacker append index N+1 with a key they control,
    ///      because they cannot forge the prior-passkey assertion.
    ///      Other INTERNAL checks: entryIndex monotonicity + contractAddress match +
    ///      P-256 (65B) + ML-KEM-768 (1184B) pubkey lengths + passkey/ML-KEM chain
    ///      continuity. Anti-collision: digest derivation uses abi.encode
    ///      (length-prefixed) per Task#13 Slither HIGH fix (commit a944b95).
    ///      DESIGN-SENSITIVE: S2-1 §13.3 binds `new_delivery_pubkey_x25519` into the
    ///      digest preimage, but the current entry struct does not yet carry the
    ///      X25519 delivery field; this contract binds every field the struct does
    ///      carry. Adding the X25519 field + the off-chain WebAuthn-framing
    ///      (clientDataJSON/authenticatorData) re-validation is the residual scope
    ///      Simon must ratify (see finding F-3).
    /// @param accountId per-subject account identifier.
    /// @param entry ABI-encoded PasskeyRotationEntry struct.
    /// @param rotationAuthorizationDigest §13.3 rotation_authorization_digest; for
    ///        entry_index ≥ 1 it is verified against the entry contents AND the
    ///        prior passkey's P-256 assertion.
    function appendRotation(bytes32 accountId, bytes calldata entry, bytes32 rotationAuthorizationDigest) external {
        _requireNotPaused(GLOBAL_SCOPE);
        PasskeyRotationEntry memory decoded = abi.decode(entry, (PasskeyRotationEntry));
        uint32 expected = _heads[accountId];
        if (decoded.entryIndex != expected) {
            revert RotationIndexNonmonotonic(accountId, expected, decoded.entryIndex);
        }
        if (decoded.contractAddress != address(this)) {
            revert RotationContractAddressMismatch(address(this), decoded.contractAddress);
        }
        if (decoded.newPubkey.length != P256_PUBKEY_LENGTH || decoded.newMlkemPubkey.length != MLKEM_768_PUBKEY_LENGTH)
        {
            revert RotationPasskeyChainBroken(accountId);
        }

        if (decoded.entryIndex == 0) {
            if (
                decoded.prevPubkey.length != 0 || decoded.prevMlkemPubkey.length != 0
                    || decoded.webauthnAssertion.length != 0
            ) {
                revert RotationPasskeyChainBroken(accountId);
            }
        } else {
            PasskeyRotationEntry memory prev =
                abi.decode(_entries[accountId][decoded.entryIndex - 1], (PasskeyRotationEntry));
            if (keccak256(decoded.prevPubkey) != keccak256(prev.newPubkey)) {
                revert RotationPasskeyChainBroken(accountId);
            }
            if (keccak256(decoded.prevMlkemPubkey) != keccak256(prev.newMlkemPubkey)) {
                revert RotationMlkemChainBroken(accountId);
            }
            // (a) bind the supplied digest to THIS entry's fields per S2-1 §13.3 —
            //     forecloses the F-3 "any non-zero digest" path.
            bytes32 boundDigest = _rotationAuthorizationDigest(accountId, decoded);
            if (rotationAuthorizationDigest != boundDigest) {
                revert RotationAuthorizationDigestMismatch(accountId, boundDigest, rotationAuthorizationDigest);
            }
            // (b)+(c) verify the prior-passkey P-256 assertion over the bound digest.
            if (!_verifyPriorPasskeyAssertion(boundDigest, decoded.webauthnAssertion, prev.newPubkey)) {
                revert RotationWebAuthnInvalid(accountId, decoded.entryIndex);
            }
        }

        _entries[accountId][decoded.entryIndex] = entry;
        _heads[accountId] = decoded.entryIndex + 1;
        emit PasskeyRotationAppended(accountId, decoded.entryIndex, keccak256(entry));
    }

    /// @notice Recomputes the S2-1 §13.3 rotation_authorization_digest over an entry.
    /// @dev Imports TAG_ROTATION_AUTHORIZATION_V3 from S2-1 §2.3.4 / §13.3. Uses
    ///      abi.encode (length-prefixed) to prevent adjacent-dynamic-arg collision,
    ///      consistent with computeRotationLogAnchor's Slither HIGH fix. Binds the
    ///      deployment (address(this)) + accountId + entryIndex + new P-256 pubkey +
    ///      new ML-KEM pubkey + timestamp. DESIGN-SENSITIVE residual: §13.3 also binds
    ///      new_delivery_pubkey_x25519, absent from the current struct (see
    ///      appendRotation NatSpec).
    function _rotationAuthorizationDigest(bytes32 accountId, PasskeyRotationEntry memory decoded)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                Tags.TAG_ROTATION_AUTHORIZATION_V3,
                address(this),
                accountId,
                decoded.entryIndex,
                decoded.newPubkey,
                decoded.newMlkemPubkey,
                decoded.timestamp
            )
        );
    }

    /// @notice Verifies a raw P-256 (secp256r1) ECDSA assertion over `digest` under
    ///         the previous entry's uncompressed passkey pubkey via RIP-7212.
    /// @dev `assertion` MUST be exactly 64 bytes (r ‖ s) — the WebAuthn raw signature
    ///      value per S2-1 §1.1.3. `prevPubkey` is the 65-byte uncompressed P-256
    ///      pubkey (0x04 ‖ x ‖ y) per WebAuthn convention; x,y are sliced from
    ///      offsets 1 and 33. Calls the RIP-7212 precompile (0x..0100) with
    ///      msgHash ‖ r ‖ s ‖ qx ‖ qy. Returns true ONLY on a 32-byte word == 1.
    ///      A missing precompile (empty return) is treated as FAILED (fail-closed),
    ///      so an unverifiable rotation is rejected rather than silently accepted.
    function _verifyPriorPasskeyAssertion(bytes32 digest, bytes memory assertion, bytes memory prevPubkey)
        internal
        view
        returns (bool)
    {
        if (assertion.length != P256_RAW_SIG_LENGTH || prevPubkey.length != P256_PUBKEY_LENGTH) {
            return false;
        }
        // Uncompressed-point prefix must be 0x04.
        if (prevPubkey[0] != 0x04) {
            return false;
        }
        bytes32 r;
        bytes32 s;
        bytes32 qx;
        bytes32 qy;
        // assertion = r(32) ‖ s(32); prevPubkey = 0x04(1) ‖ qx(32) ‖ qy(32).
        // memory layout: byte 0 is the 32-byte length word, payload starts at +0x20.
        assembly {
            r := mload(add(assertion, 0x20))
            s := mload(add(assertion, 0x40))
            qx := mload(add(prevPubkey, 0x21))
            qy := mload(add(prevPubkey, 0x41))
        }
        bytes memory input = abi.encodePacked(digest, r, s, qx, qy);
        (bool ok, bytes memory ret) = RIP7212_P256_VERIFY.staticcall(input);
        if (!ok || ret.length != 32) {
            // Precompile absent / errored → fail-closed.
            return false;
        }
        return abi.decode(ret, (uint256)) == 1;
    }

    function getHead(bytes32 accountId) external view returns (uint32) {
        if (_heads[accountId] == 0) {
            revert RotationAccountUnknown(accountId);
        }
        return _heads[accountId] - 1;
    }

    function getEntry(bytes32 accountId, uint32 entryIndex) external view returns (bytes memory entry) {
        if (entryIndex >= _heads[accountId]) {
            revert RotationAccountUnknown(accountId);
        }
        return _entries[accountId][entryIndex];
    }

    /// @notice Returns a paginated range of rotation entries.
    /// @dev View. Half-open range [fromInclusive, toExclusive). Reverts
    ///      RotationRangeInvalid if (a) fromInclusive >= toExclusive,
    ///      (b) toExclusive exceeds head, or (c) range size exceeds
    ///      MAX_PAGE_SIZE (64) — DoS bound to keep view-call gas predictable
    ///      under default Geth/Erigon archive-node limits. Consumers paginate
    ///      via successive calls when iterating a long rotation history.
    function getEntries(bytes32 accountId, uint32 fromInclusive, uint32 toExclusive)
        external
        view
        returns (bytes[] memory entries)
    {
        if (
            fromInclusive >= toExclusive || toExclusive > _heads[accountId]
                || toExclusive - fromInclusive > MAX_PAGE_SIZE
        ) {
            revert RotationRangeInvalid(accountId, fromInclusive, toExclusive);
        }
        entries = new bytes[](toExclusive - fromInclusive);
        for (uint32 i = fromInclusive; i < toExclusive; ++i) {
            entries[i - fromInclusive] = _entries[accountId][i];
        }
    }

    function computeRotationLogAnchor(
        address contractAddress,
        bytes32 accountId,
        uint32 entryIndex,
        bytes calldata passkeyPubkey,
        bytes calldata mlkemPubkey
    ) external pure returns (bytes32) {
        // abi.encode (length-prefixed) prevents collision between multiple
        // dynamic byte args. abi.encodePacked would let hash(abc|de) == hash(ab|cde)
        // for adjacent dynamic args. See Slither detector encode-packed-collision.
        return keccak256(
            abi.encode(
                Tags.TAG_ROTATION_LOG_ANCHOR_V3, contractAddress, accountId, entryIndex, passkeyPubkey, mlkemPubkey
            )
        );
    }

    function _requireNotPaused(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert RotationPaused(scope);
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

    uint256[50] private __gap;
}
