// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {
    AccessControlUpgradeable,
    GovernedRegistry,
    PausableUpgradeable,
    RegistryInvalidEntry,
    RegistryLookupKeyMismatch
} from "./PluginHashRegistry.sol";
import { Roles } from "../lib/Roles.sol";
import { Tags } from "../lib/Tags.sol";
import { DeprecationFlag } from "../lib/Structs.sol";

/// @title OracleRegistry - authorized oracle publisher registry (class-CRYPTO)
/// @notice One of the 5 Cealis-governed V3 registries. Records oracle identities
///         (Chainlink feeds, drand time-anchors, QTSP-signed events, regulator
///         attesters) authorized to feed evidence into OracleAttestationModule
///         predicates. Pairs with OracleSchemaRegistry: oracle → schema → claim
///         predicate flow.
/// @dev Class-CRYPTO key discipline: oracleId =
///      keccak256(TAG_ORACLE_REGISTRY_V3 || oraclePubkeyOrAddress). Trust-tier
///      pinning per PDA via trustTier field — PDA's trust-tier-to-oracle-tier
///      consistency rule (S2-4 §6) ensures PDA NEVER references an oracle of
///      tier below its declared minimum. canonicalExamplesHash binds the
///      expected-payload examples for off-chain spec verification.
contract OracleRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    GovernedRegistry
{
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

    mapping(bytes32 => OracleEntry) private _oracles;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address securityCouncil, address emergencyGovernance, address pauser)
        public
        initializer
    {
        __AccessControl_init();
        __Pausable_init();
        _initializeRegistry(timelock, securityCouncil, emergencyGovernance, pauser);
    }

    /// @notice Computes the canonical oracleId for a given pubkey/address.
    /// @dev Pure helper. Formula: keccak256(TAG_ORACLE_REGISTRY_V3 || oraclePubkeyOrAddress).
    ///      Class-CRYPTO key discipline boundary: TAG-prefix prevents
    ///      cross-registry-class collisions even when oraclePubkeyOrAddress
    ///      is a bare 20-byte EVM address or a longer non-EVM pubkey.
    function computeOracleId(bytes calldata oraclePubkeyOrAddress) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(Tags.TAG_ORACLE_REGISTRY_V3, oraclePubkeyOrAddress));
    }

    /// @notice Registers an oracle publisher in the canonical registry.
    /// @dev Access: REGISTRY_ADMIN_ROLE (timelock-bound). Invariants:
    ///      oraclePubkeyOrAddress MUST be non-empty; schemaId MUST be
    ///      non-zero (binds the oracle to its declared payload schema in
    ///      OracleSchemaRegistry); oracleId MUST equal computeOracleId(
    ///      oraclePubkeyOrAddress) — RegistryLookupKeyMismatch otherwise.
    ///      deprecationFlag is forcibly zeroed at add-time.
    function addOracle(bytes32 oracleId, OracleEntry calldata entry)
        external
        onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE)
    {
        if (entry.oraclePubkeyOrAddress.length == 0 || entry.schemaId == bytes32(0)) {
            revert RegistryInvalidEntry(oracleId);
        }
        bytes32 expected = computeOracleId(entry.oraclePubkeyOrAddress);
        if (oracleId != expected) revert RegistryLookupKeyMismatch(expected, oracleId);

        OracleEntry memory stored = entry;
        stored.deprecationFlag = _zeroFlag();
        _oracles[oracleId] = stored;
        _recordEntry(oracleId, entry.effectiveBlock, entry.tombstoneBlock, entry.isCanonical);
    }

    /// @notice Returns the oracle entry as it stood at a specific block.
    /// @dev Point-in-time reading discipline per S2-3 §11: OracleAttestationModule
    ///      submitters MUST read at commit_block, not at attestation-submission
    ///      block. Prevents mid-flight oracle deprecation from invalidating
    ///      in-flight attestations against commits made under the prior valid
    ///      tier/schema. Reverts RegistryEntryUnknown / RegistryEntryNotEffective /
    ///      RegistryEntryTombstoned as appropriate.
    function getOracleAt(bytes32 oracleId, uint64 blockNumber) public view returns (OracleEntry memory) {
        EntryMeta memory meta = _metaAt(oracleId, blockNumber);
        OracleEntry memory entry = _oracles[oracleId];
        entry.effectiveBlock = meta.effectiveBlock;
        entry.tombstoneBlock = meta.tombstoneBlock;
        entry.isCanonical = meta.isCanonical;
        entry.deprecationFlag = _deprecationFlagAt(oracleId, blockNumber);
        return entry;
    }

    /// @notice Returns the current Oracle entry for the given id.
    /// @dev IBaseRegistry interface implementation. View-only. For at-commit-block
    ///      reading discipline (§1.3 NORMATIVE) use getEntryAt instead.
    function getEntry(bytes32 id) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getOracleAt(id, _currentBlock()));
    }

    /// @notice Returns the Oracle entry as it was at `blockNumber`.
    /// @dev IBaseRegistry interface implementation. Implements at-commit-block
    ///      reading discipline per §1.3 NORMATIVE — caller MUST pass commit_block.
    ///      Class-CRYPTO registry (TAG_ORACLE_REGISTRY_V3-prefixed lookup-key) per
    ///      internal design record v3-registry-class-discipline.md.
    function getEntryAt(bytes32 id, uint64 blockNumber) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getOracleAt(id, blockNumber));
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
