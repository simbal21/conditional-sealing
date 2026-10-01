// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {
    AccessControlUpgradeable,
    GovernedRegistry,
    PausableUpgradeable,
    RegistryInvalidEntry
} from "./PluginHashRegistry.sol";
import { Roles } from "../lib/Roles.sol";
import { DeprecationFlag } from "../lib/Structs.sol";

error OracleSchemaUnknown(bytes32 schemaId);

event OracleSchemaAdded(
    bytes32 indexed schemaId,
    bytes32 schemaHash,
    bytes32 validExamplesHash,
    bytes32 invalidExamplesHash,
    uint64 effectiveBlock
);

/// @title OracleSchemaRegistry - oracle payload schema registry (class-CATALOG)
/// @notice One of the 5 Cealis-governed V3 registries. Records canonical payload
///         schemas for OracleAttestationModule predicates (e.g., Chainlink-price-
///         feed schema, drand-time-anchor schema, QTSP-eIDAS schema). Pairs with
///         OracleRegistry: oracleId references schemaId, AttestationGate uses
///         the schema to constrain partner-supplied claims at verify time.
/// @dev Class-CATALOG discipline (per internal design record `v3-registry-class-discipline.md`):
///      schemaId is a CONFIGURED raw 32-byte ref (NOT TAG-prefixed) — domain
///      separation comes from upstream wrapping in TAG_AAD_V3 / pda_root.
///      schemaHash binds the off-chain JSON-schema bytes; validExamplesHash +
///      invalidExamplesHash bind fuzz-corpus references so partners +
///      auditors can verify the gate's schema-conformance independent of any
///      one oracle. supportedOracleTypesMask gates which oracle-types may
///      reference this schema (uint256 bitfield).
contract OracleSchemaRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    GovernedRegistry
{
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

    mapping(bytes32 => OracleSchemaEntry) private _schemas;

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

    /// @notice Registers an oracle payload schema in the canonical registry.
    /// @dev Access: REGISTRY_ADMIN_ROLE (timelock-bound). Invariants:
    ///      schemaHash MUST be non-zero (binds the canonical schema bytes);
    ///      supportedOracleTypesMask MUST be non-zero (at least one oracle-type
    ///      authorized to use this schema). schemaVersion enables ordered schema
    ///      evolution without breaking historical commits. deprecationFlag is
    ///      forcibly zeroed at add-time.
    function addSchema(bytes32 schemaId, OracleSchemaEntry calldata entry)
        external
        onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE)
    {
        if (entry.schemaHash == bytes32(0) || entry.supportedOracleTypesMask == 0) {
            revert RegistryInvalidEntry(schemaId);
        }
        OracleSchemaEntry memory stored = entry;
        stored.deprecationFlag = _zeroFlag();
        _schemas[schemaId] = stored;
        _recordEntry(schemaId, entry.effectiveBlock, entry.tombstoneBlock, entry.isCanonical);
        emit OracleSchemaAdded(
            schemaId, entry.schemaHash, entry.validExamplesHash, entry.invalidExamplesHash, entry.effectiveBlock
        );
    }

    /// @notice Returns the current schema entry for schemaId.
    /// @dev View. Reverts OracleSchemaUnknown if schemaId is unregistered.
    ///      For point-in-time reads (commit_block), use getSchemaAt directly.
    function getSchema(bytes32 schemaId) external view returns (OracleSchemaEntry memory) {
        if (!_entryMeta[schemaId].exists) revert OracleSchemaUnknown(schemaId);
        return getSchemaAt(schemaId, _currentBlock());
    }

    /// @notice Returns the schema entry as it stood at a specific block.
    /// @dev Point-in-time reading discipline: AttestationGate.verifyOracleAttestation
    ///      MUST read schemas at commit_block (PDA's effective block) to avoid
    ///      mid-flight schema revisions invalidating historical commits.
    ///      Returns deprecationFlag-at-block (not current).
    function getSchemaAt(bytes32 schemaId, uint64 blockNumber) public view returns (OracleSchemaEntry memory) {
        if (!_entryMeta[schemaId].exists) revert OracleSchemaUnknown(schemaId);
        EntryMeta memory meta = _metaAt(schemaId, blockNumber);
        OracleSchemaEntry memory entry = _schemas[schemaId];
        entry.effectiveBlock = meta.effectiveBlock;
        entry.tombstoneBlock = meta.tombstoneBlock;
        entry.isCanonical = meta.isCanonical;
        entry.deprecationFlag = _deprecationFlagAt(schemaId, blockNumber);
        return entry;
    }

    /// @notice Returns the current Oracle schema entry for the given id.
    /// @dev IBaseRegistry interface implementation. View-only. _metaAt enforces the
    ///      existence check at current block.
    function getEntry(bytes32 id) external view override returns (bytes memory encodedEntry) {
        _metaAt(id, _currentBlock());
        return abi.encode(getSchemaAt(id, _currentBlock()));
    }

    /// @notice Returns the Oracle schema entry as it was at `blockNumber`.
    /// @dev §1.3 NORMATIVE at-commit-block discipline. Schemas pair with OracleRegistry
    ///      entries: every schema is reachable via schemaId only at the registered
    ///      effective_block (tombstone tuple). Used by AttestationGate at
    ///      verifyOracleAttestation time to constrain partner-supplied claims.
    function getEntryAt(bytes32 id, uint64 blockNumber) external view override returns (bytes memory encodedEntry) {
        _metaAt(id, blockNumber);
        return abi.encode(getSchemaAt(id, blockNumber));
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
