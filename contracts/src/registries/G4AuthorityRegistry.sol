// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {
    AccessControlUpgradeable,
    GovernedRegistry,
    PausableUpgradeable,
    RegistryInvalidEntry,
    RegistryLookupKeyMismatch,
    RegistryZeroAddress
} from "./PluginHashRegistry.sol";
import { ICealisIdentifierHelpers } from "../helpers/ICealisIdentifierHelpers.sol";
import { Roles } from "../lib/Roles.sol";
import { DeprecationFlag } from "../lib/Structs.sol";

/// @title G4AuthorityRegistry - authorized G4 attestation-signer registry (class-CRYPTO)
/// @notice One of the 5 Cealis-governed V3 registries. Records authorized G4
///         verification components (Phase 1 sealed-code server pubkeys; Phase 2
///         HSM/TEE-attested pubkeys). G4 is the 4th gate in the V3 AND-composition
///         {Lit V3, G3, G4} — its signature σ_G4 is required for any reveal to
///         complete. This registry is the on-chain root-of-trust for which G4
///         identities may sign.
/// @dev Class-CRYPTO discipline (per internal design record `v3-registry-class-discipline.md`):
///      lookup key MUST equal TAG_G4_ATTESTATION_AUTHORITY_V3-prefixed keccak
///      of the authority pubkey, eliminating raw-pubkey collisions across
///      registry classes. Phase split: phase=1 (server) or phase=2 (HSM/TEE);
///      binaryHashOrMeasurement encodes either canonical-binary hash (Phase 1)
///      or DCAP TEE measurement (Phase 2). dcapVerifierRef binds the DCAP
///      verifier contract for Phase 2. Pubkey retirement: G4 0x07 (Phase 2-only
///      authority retired) and 0x09 (Phase 1 sealed-code server retired) refusal
///      codes complete the crypto-non-custody invariant on this layer.
contract G4AuthorityRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    GovernedRegistry
{
    struct G4AuthorityEntry {
        uint8 phase;
        bytes authorityPubkey;
        bytes32 binaryHashOrMeasurement;
        bytes32 dcapVerifierRef;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    ICealisIdentifierHelpers public identifierHelpers;
    mapping(bytes32 => G4AuthorityEntry) private _authorities;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address timelock,
        address securityCouncil,
        address emergencyGovernance,
        address pauser,
        address operator,
        address identifierHelpers_
    ) public initializer {
        __AccessControl_init();
        __Pausable_init();
        if (operator == address(0) || identifierHelpers_ == address(0)) revert RegistryZeroAddress();
        identifierHelpers = ICealisIdentifierHelpers(identifierHelpers_);
        _initializeRegistry(timelock, securityCouncil, emergencyGovernance, pauser);
        _registryGrantRole(Roles.OPERATOR_ROLE, operator);
    }

    /// @notice Registers a G4 attestation-signer in the canonical registry.
    /// @dev Access: REGISTRY_ADMIN_ROLE (timelock-bound). Invariants:
    ///      authorityPubkey MUST be non-empty; phase MUST be 1 (sealed-code
    ///      server) or 2 (HSM/TEE). Class-CRYPTO key discipline:
    ///      g4AuthorityRef MUST equal computeG4AuthorityRef(authorityPubkey) =
    ///      keccak256(TAG_G4_ATTESTATION_AUTHORITY_V3 || authorityPubkey).
    ///      Mismatch reverts RegistryLookupKeyMismatch. deprecationFlag is
    ///      forcibly zeroed (deprecation = post-add governance action).
    function addG4Authority(bytes32 g4AuthorityRef, G4AuthorityEntry calldata entry)
        external
        onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE)
    {
        if (entry.authorityPubkey.length == 0 || (entry.phase != 1 && entry.phase != 2)) {
            revert RegistryInvalidEntry(g4AuthorityRef);
        }
        bytes32 expected = identifierHelpers.computeG4AuthorityRef(entry.authorityPubkey);
        if (g4AuthorityRef != expected) revert RegistryLookupKeyMismatch(expected, g4AuthorityRef);

        G4AuthorityEntry memory stored = entry;
        stored.deprecationFlag = _zeroFlag();
        _authorities[g4AuthorityRef] = stored;
        _recordEntry(g4AuthorityRef, entry.effectiveBlock, entry.tombstoneBlock, entry.isCanonical);
    }

    /// @notice Returns the G4 authority entry as it stood at a specific block.
    /// @dev Point-in-time reading discipline per S2-3 §11: combiners + G4 verifiers
    ///      MUST read at commit_block, not gate-signing block — prevents mid-flight
    ///      authority retraction from re-keying existing commits. Reverts
    ///      RegistryEntryUnknown / RegistryEntryNotEffective / RegistryEntryTombstoned
    ///      as appropriate. deprecationFlag returned is the checkpoint-at-block value.
    function getG4AuthorityAt(bytes32 g4AuthorityRef, uint64 blockNumber)
        public
        view
        returns (G4AuthorityEntry memory)
    {
        EntryMeta memory meta = _metaAt(g4AuthorityRef, blockNumber);
        G4AuthorityEntry memory entry = _authorities[g4AuthorityRef];
        entry.effectiveBlock = meta.effectiveBlock;
        entry.tombstoneBlock = meta.tombstoneBlock;
        entry.isCanonical = meta.isCanonical;
        entry.deprecationFlag = _deprecationFlagAt(g4AuthorityRef, blockNumber);
        return entry;
    }

    /// @notice Returns the current G4 authority entry for the given id.
    /// @dev IBaseRegistry interface implementation. View-only. For at-commit-block
    ///      reading discipline (§1.3 NORMATIVE) use getEntryAt instead.
    function getEntry(bytes32 id) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getG4AuthorityAt(id, _currentBlock()));
    }

    /// @notice Returns the G4 authority entry as it was at `blockNumber`.
    /// @dev IBaseRegistry interface implementation. Implements at-commit-block
    ///      reading discipline per §1.3 NORMATIVE — caller MUST pass commit_block.
    ///      Class-CRYPTO registry (TAG-prefixed lookup-key) per
    ///      internal design record v3-registry-class-discipline.md (TAG_G4_ATTESTATION_AUTHORITY_V3).
    function getEntryAt(bytes32 id, uint64 blockNumber) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getG4AuthorityAt(id, blockNumber));
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }

    function _registryHasRole(bytes32 role, address account) internal view override returns (bool) {
        return hasRole(role, account);
    }

    function _registryGrantRole(bytes32 role, address account) internal override {
        _grantRole(role, account);
    }

    function _registrySetRoleAdmin(bytes32 role, bytes32 adminRole) internal override {
        _setRoleAdmin(role, adminRole);
    }

    uint256[50] private __gap;
}
