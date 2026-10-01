// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { IAttestationGate, IClaimDSL } from "../engine/IConditionEngine.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";
import { DeprecationFlag } from "../lib/Structs.sol";
import { Tags } from "../lib/Tags.sol";

interface IOracleRegistryD1 {
    struct OracleEntry {
        bytes oraclePubkeyOrAddress;
        uint8 oracleType;
        bytes32 schemaId;
        bytes32 canonicalExamplesHash;
        uint8 trustTier;
        bytes32 metadataHash;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    function getOracleAt(bytes32 oracleId, uint64 blockNumber) external view returns (OracleEntry memory);
}

interface IOracleSchemaRegistryD1 {
    struct OracleSchemaEntry {
        bytes32 schemaHash;
        bytes32 validExamplesHash;
        bytes32 invalidExamplesHash;
        uint32 schemaVersion;
        bytes32 metadataHash;
        uint256 supportedOracleTypesMask;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    function getSchemaAt(bytes32 schemaId, uint64 blockNumber) external view returns (OracleSchemaEntry memory);
}

/// @title AttestationGate - oracle attestation verification + claim evaluation surface
/// @notice Central on-chain validator for oracle-signed attestations consumed by
///         OracleAttestationModule. Performs the full chain of checks: oracle
///         registered + non-deprecated at commit_block, schema matches and is
///         registered, attestation digest fresh (within configured age window),
///         oracle signature valid (secp256k1 recover), DSL-encoded claim evaluates
///         to true. Used by ALL condition modules whose predicate ultimately
///         depends on off-chain evidence.
/// @dev Hostile-bytes guard: σ-shaped inputs (96 bytes, the canonical σ_Lit /
///      σ_G3 / σ_G4 length) are REJECTED at the signature surface
///      (AttestationSigmaBytesForbidden) — defense-in-depth boundary preventing
///      accidental σ-as-IKM regression per the May 2026 σ-as-authorization
///      doctrine lock. Try/catch around registry reads converts revert paths
///      into typed AttestationGate errors for callers (separation of concerns:
///      this contract owns its error surface, not the registries'). Pause
///      semantics: BoundedPausable global-scope, PAUSER_ROLE.
contract AttestationGate is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable, IAttestationGate {
    uint8 private constant ORACLE_TYPE_SECP256K1 = 1;
    uint256 private constant SIGMA_SHAPED_BYTES = 96;
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    IOracleRegistryD1 private _oracleRegistry;
    IOracleSchemaRegistryD1 private _oracleSchemaRegistry;
    address private _dslVersionRegistry;
    IClaimDSL private _claimDsl;

    mapping(bytes32 => uint64) private _authorizationBlocks;
    mapping(bytes32 => bytes32) private _claimDslVersions;
    mapping(bytes32 => uint64) private _attestationObservedAt;
    uint64 private _maxAttestationAgeSeconds;
    // BR-F: gate-level single-use nullifier set. Defense-in-depth beyond the
    // OracleAttestationModule wrapper's _consumedAttestations — any future caller
    // of this reusable verifier (MultiPartySignal oracle path, tryEvaluate*, etc.)
    // inherits once-and-only-once consumption per attestationDigest from the gate
    // itself rather than relying on the wrapper to carry its own replay set.
    mapping(bytes32 => bool) private _consumedAttestationDigests;

    event AuthorizationBlockPinned(bytes32 indexed authorizationId, uint64 authorizationBlock);
    event ClaimDSLVersionPinned(bytes32 indexed claimRef, bytes32 indexed dslVersionRef);
    event AttestationObservedAtPinned(bytes32 indexed attestationDigest, uint64 observedAt);

    error AttestationPaused(bytes32 scope);
    // BR-F: raised when the same attestationDigest is verified more than once at the gate.
    error AttestationDigestConsumed(bytes32 attestationDigest);

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address timelock,
        address oracleRegistry,
        address oracleSchemaRegistry,
        address dslVersionRegistry,
        address claimDsl
    ) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
        _grantRole(Roles.OPERATOR_ROLE, timelock);
        _oracleRegistry = IOracleRegistryD1(oracleRegistry);
        _oracleSchemaRegistry = IOracleSchemaRegistryD1(oracleSchemaRegistry);
        _dslVersionRegistry = dslVersionRegistry;
        _claimDsl = IClaimDSL(claimDsl);
        _maxAttestationAgeSeconds = 1 days;
    }

    /// @notice Pins the commit_block to use for registry point-in-time reads for this authorizationId.
    /// @dev OPERATOR_ROLE only. Used to enforce "at-commit-block discipline" per
    ///      S2-3 §11 — registry lookups for oracle + schema use this pinned
    ///      block, NOT the current block. If unset (0), verifyOracleAttestation
    ///      falls back to block.number at call time. Pinning at PDA commit
    ///      time prevents mid-flight registry updates from invalidating
    ///      in-flight attestations.
    function setAuthorizationBlock(bytes32 authorizationId, uint64 pinnedAuthorizationBlock)
        external
        onlyRole(Roles.OPERATOR_ROLE)
    {
        _authorizationBlocks[authorizationId] = pinnedAuthorizationBlock;
        emit AuthorizationBlockPinned(authorizationId, pinnedAuthorizationBlock);
    }

    /// @notice Pins a DSL version reference for a given claimRef.
    /// @dev OPERATOR_ROLE only. Used at attestation evaluation time to resolve which
    ///      ClaimDSL bytecode to execute. Re-pinning overwrites the prior version.
    function setClaimDSLVersion(bytes32 claimRef, bytes32 dslVersionRef) external onlyRole(Roles.OPERATOR_ROLE) {
        _claimDslVersions[claimRef] = dslVersionRef;
        emit ClaimDSLVersionPinned(claimRef, dslVersionRef);
    }

    /// @notice Records the observed-at block timestamp for a given attestationDigest.
    /// @dev OPERATOR_ROLE only. Used in freshness-window enforcement (compared against
    ///      _maxAttestationAgeSeconds + block.timestamp).
    function setAttestationObservedAt(bytes32 attestationDigest, uint64 observedAt)
        external
        onlyRole(Roles.OPERATOR_ROLE)
    {
        _attestationObservedAt[attestationDigest] = observedAt;
        emit AttestationObservedAtPinned(attestationDigest, observedAt);
    }

    /// @notice Sets the maximum acceptable attestation age in seconds (freshness window).
    /// @dev OPERATOR_ROLE only. Zero disables freshness check. Used in
    ///      verifyOracleAttestation to reject stale attestations.
    function setMaxAttestationAgeSeconds(uint64 maxAge) external onlyRole(Roles.OPERATOR_ROLE) {
        _maxAttestationAgeSeconds = maxAge;
    }

    /// @notice Verifies an oracle attestation through the full validation chain.
    /// @dev Permissionless (any caller — typically OracleAttestationModule). Pause-gated.
    ///      Validation order (FAIL-CLOSED at each step):
    ///        1. σ-shape guard: reject 96-byte signatures (σ-as-authorization defense).
    ///        2. Single-use guard (BR-F): reject an already-consumed attestationDigest.
    ///        3. Authorization-block resolution (pinned vs current).
    ///        4. Oracle registry lookup at pinned block — must exist + not deprecated.
    ///        5. Schema match: oracleEntry.schemaId == passed schemaId.
    ///        6. Schema registry lookup at pinned block — schemaHash non-zero.
    ///        7. Freshness: observed-at + maxAge > now (auto-records if unset).
    ///        8. Signature: secp256k1 recover over the CHAIN-BOUND preimage
    ///           keccak(TAG_ATTESTATION_CONTEXT_V3 ‖ block.chainid ‖ authorizationId ‖
    ///           schemaId ‖ attestationDigest) matches oracle pubkey (F-02 cross-chain
    ///           replay defense — the off-chain oracle signing construction in the
    ///           S2-3 SDK MUST sign over this same preimage; coordinated change).
    ///        9. Claim DSL evaluation: pinned dslVersionRef interpreter returns true.
    ///      Side effects: lazily sets _attestationObservedAt[digest] on first sight;
    ///      marks _consumedAttestationDigests[digest] on success (single-use).
    function verifyOracleAttestation(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes calldata oracleSignature,
        bytes32 claimRef
    ) external returns (bool) {
        _requireNotPaused();
        if (oracleSignature.length == SIGMA_SHAPED_BYTES) revert AttestationSigmaBytesForbidden();
        if (_consumedAttestationDigests[attestationDigest]) revert AttestationDigestConsumed(attestationDigest);
        uint64 pinnedAuthorizationBlock = _authorizationBlocks[authorizationId];
        if (pinnedAuthorizationBlock == 0) pinnedAuthorizationBlock = uint64(block.number);

        // slither-disable-next-line uninitialized-local -- assigned in the try-branch below; the catch-branch reverts, so oracleEntry is provably initialized before any use
        IOracleRegistryD1.OracleEntry memory oracleEntry;
        try _oracleRegistry.getOracleAt(oracleId, pinnedAuthorizationBlock) returns (
            IOracleRegistryD1.OracleEntry memory entry
        ) {
            oracleEntry = entry;
        } catch {
            revert AttestationOracleUnknown(oracleId);
        }
        if (oracleEntry.schemaId != schemaId) revert AttestationSchemaMismatch(oracleId, schemaId);

        try _oracleSchemaRegistry.getSchemaAt(schemaId, pinnedAuthorizationBlock) returns (
            IOracleSchemaRegistryD1.OracleSchemaEntry memory schemaEntry
        ) {
            // slither-disable-next-line incorrect-equality -- bytes32(0) is the registry "schema unset" sentinel; exact-zero check is correct
            if (schemaEntry.schemaHash == bytes32(0)) revert AttestationSchemaMismatch(oracleId, schemaId);
        } catch {
            revert AttestationSchemaMismatch(oracleId, schemaId);
        }

        uint64 observedAt = _attestationObservedAt[attestationDigest];
        // slither-disable-next-line incorrect-equality -- 0 is the "never observed" sentinel for the observed-at timestamp; exact-zero check is correct
        if (observedAt == 0) {
            observedAt = uint64(block.timestamp);
            _attestationObservedAt[attestationDigest] = observedAt;
        }
        if (_maxAttestationAgeSeconds != 0 && observedAt + _maxAttestationAgeSeconds < block.timestamp) {
            revert AttestationStale(attestationDigest);
        }

        // F-02: recover over a chain-bound preimage, not the raw caller-supplied digest,
        // so a signature minted for one chain (e.g. Base Sepolia) cannot be replayed on
        // another (e.g. Base Mainnet) where the same oracle key may be reused.
        bytes32 signingDigest = _chainBoundSigningDigest(authorizationId, schemaId, attestationDigest);
        if (!_verifySignature(oracleEntry, signingDigest, oracleSignature)) {
            revert AttestationSignatureInvalid(oracleId, attestationDigest);
        }

        bytes32 dslVersionRef = _claimDslVersions[claimRef];
        bool claimOk = _claimDsl.evaluateClaim(dslVersionRef, claimRef, attestationDigest);
        if (!claimOk) revert AttestationClaimFalse(claimRef);

        // BR-F: burn the digest only after the full chain passes — a failed verify
        // reverts before reaching here, so a legitimate retry of a not-yet-accepted
        // digest is not griefed by a prior failed attempt.
        _consumedAttestationDigests[attestationDigest] = true;

        emit OracleAttestationAccepted(authorizationId, oracleId, attestationDigest, schemaId, claimRef);
        return true;
    }

    /// @notice Whether an attestationDigest has already been consumed at the gate (BR-F).
    function attestationDigestConsumed(bytes32 attestationDigest) external view returns (bool) {
        return _consumedAttestationDigests[attestationDigest];
    }

    /// @notice Reconstructs the chain-bound preimage the oracle must sign (F-02).
    /// @dev TAG-prefixed domain separation per TAG_*_V3 discipline, binding block.chainid
    ///      so cross-chain replay is structurally impossible. The off-chain oracle signer
    ///      (S2-3 SDK) MUST produce ECDSA signatures over this exact preimage. Exposed as a
    ///      view so the SDK + integration tests can assert byte-for-byte agreement.
    function chainBoundSigningDigest(bytes32 authorizationId, bytes32 schemaId, bytes32 attestationDigest)
        external
        view
        returns (bytes32)
    {
        return _chainBoundSigningDigest(authorizationId, schemaId, attestationDigest);
    }

    function _chainBoundSigningDigest(bytes32 authorizationId, bytes32 schemaId, bytes32 attestationDigest)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                Tags.TAG_ATTESTATION_CONTEXT_V3, block.chainid, authorizationId, schemaId, attestationDigest
            )
        );
    }

    function tryEvaluateOracleAttestation(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes calldata oracleSignature,
        bytes32 claimRef
    ) external returns (bool ok) {
        try this.verifyOracleAttestation(
            authorizationId, oracleId, schemaId, attestationDigest, oracleSignature, claimRef
        ) returns (
            bool result
        ) {
            return result;
        } catch {
            return false;
        }
    }

    function authorizationBlock(bytes32 authorizationId) external view returns (uint64) {
        return _authorizationBlocks[authorizationId];
    }

    function claimDslVersion(bytes32 claimRef) external view returns (bytes32) {
        return _claimDslVersions[claimRef];
    }

    function dependencyAddresses()
        external
        view
        returns (address oracleRegistry, address oracleSchemaRegistry, address dslVersionRegistry, address claimDsl)
    {
        return (address(_oracleRegistry), address(_oracleSchemaRegistry), _dslVersionRegistry, address(_claimDsl));
    }

    function _verifySignature(
        IOracleRegistryD1.OracleEntry memory oracleEntry,
        bytes32 signingDigest,
        bytes calldata oracleSignature
    ) private pure returns (bool) {
        if (oracleEntry.oracleType != ORACLE_TYPE_SECP256K1 || oracleSignature.length != 65) {
            return false;
        }
        address expected = _oracleAddress(oracleEntry.oraclePubkeyOrAddress);
        if (expected == address(0)) return false;
        // F-02: signingDigest is the chain-bound preimage hash, NOT the raw attestationDigest.
        return ECDSA.recover(signingDigest, oracleSignature) == expected;
    }

    /// @notice Decodes a bytes-encoded oracle pubkey/address into an EVM address.
    /// @dev Two assembly blocks (only assembly usage in the entire V3 contract surface):
    ///
    ///      BLOCK 1 (length=20, raw EVM address bytes):
    ///        `oracle := shr(96, mload(add(oraclePubkeyOrAddress, 32)))`
    ///      Memory layout: `oraclePubkeyOrAddress` is `bytes memory`, so the first
    ///      32 bytes at its pointer hold the length prefix; the actual 20-byte address
    ///      starts at offset +32. `mload(add(ptr, 32))` reads 32 bytes starting there,
    ///      but the address occupies the HIGH 20 bytes — the low 12 bytes are
    ///      garbage from the next memory word. `shr(96, …)` right-shifts by 96 bits
    ///      (= 12 bytes) to align the address to the low-order bits of the result.
    ///      Equivalent to `address(uint160(uint256(bytes32(slice[0:20] ‖ 0^12))))`
    ///      but more gas-efficient. SAFETY: length check (`== 20`) gates entry, so
    ///      the read is in-bounds within the allocated bytes buffer.
    ///
    ///      BLOCK 2 (length=32, full 32-byte word with address as low 20 bytes):
    ///        `encoded := mload(add(oraclePubkeyOrAddress, 32))`
    ///      Reads the 32-byte word at offset +32 (skipping length prefix). Then a
    ///      Solidity-level cast `address(uint160(uint256(encoded)))` truncates to
    ///      the low 20 bytes. SAFETY: length check (`== 32`) gates entry, so the
    ///      read is in-bounds.
    ///
    ///      Returns address(0) for any other length (length-not-20-or-32 paths fall
    ///      through to the implicit return of the zero-initialized `oracle` named
    ///      return). Callers (verifyOracleAttestation L218) treat `address(0)` as
    ///      "invalid pubkey" and revert AttestationSignatureInvalid.
    ///
    ///      AUDIT REVIEW NOTE (2026-05-14, Cat 8 Low-level deliverable): These are
    ///      the ONLY two assembly blocks in the entire V3 contract surface (verified
    ///      via `grep -rn assembly src/`). All other low-level operations use OZ
    ///      ReentrancyGuardTransient (transient storage, EVM Cancun, OZ-audited) or
    ///      standard Solidity primitives.
    // slither-disable-start incorrect-equality
    // -- exact-length discriminator: 20 bytes = packed EVM address, 32 bytes = padded pubkey word.
    //    A range comparison would silently misparse malformed inputs; strict length equality is required.
    function _oracleAddress(bytes memory oraclePubkeyOrAddress) private pure returns (address oracle) {
        if (oraclePubkeyOrAddress.length == 20) {
            assembly {
                oracle := shr(96, mload(add(oraclePubkeyOrAddress, 32)))
            }
        } else if (oraclePubkeyOrAddress.length == 32) {
            bytes32 encoded;
            assembly {
                encoded := mload(add(oraclePubkeyOrAddress, 32))
            }
            oracle = address(uint160(uint256(encoded)));
        }
    }
    // slither-disable-end incorrect-equality

    function _requireNotPaused() private view {
        if (_pauses[GLOBAL_SCOPE].until != 0 && block.timestamp < _pauses[GLOBAL_SCOPE].until) {
            revert AttestationPaused(GLOBAL_SCOPE);
        }
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (!hasRole(Roles.PAUSER_ROLE, caller)) revert PauseUnauthorized(scope, caller);
    }

    function _maxPauseDuration() internal pure override returns (uint64) {
        return PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
    }

    function _pauseAuthorityMode(bytes32) internal pure override returns (PauseAuthorityMode) {
        return PauseAuthorityMode.Joint;
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }

    // __gap reduced 50 -> 49 to absorb the appended _consumedAttestationDigests mapping
    // (BR-F) while keeping the total reserved storage footprint upgrade-stable.
    uint256[49] private __gap;
}
