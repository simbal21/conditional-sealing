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

/// @title DSLVersionRegistry - Claim DSL interpreter version registry (class-CATALOG)
/// @notice One of the 5 Cealis-governed V3 registries. Records authorized Claim
///         DSL interpreters by version: each entry pins a deployed ClaimDSL
///         contract address + the capabilities-set hash (capSetHash) it
///         implements. PDAs declare a dslVersion field; ClaimDSL.evaluateClaim
///         is resolved through this registry at commit_block.
/// @dev Class-CATALOG discipline (per internal design record `v3-registry-class-discipline.md`):
///      dslVersionRef is a CONFIGURED raw 32-byte ref (NOT TAG-prefixed) —
///      domain separation comes from upstream wrapping in TAG_AAD_V3 / pda_root.
///      capSetHash binds the capability surface (set of supported claim
///      operators + WASM predicate hooks). customPredicateEnabled toggles
///      Stage-2 §6 WASM-predicate execution; OFF for stricter audit tiers.
contract DSLVersionRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    GovernedRegistry
{
    struct DSLVersionEntry {
        address interpreter;
        bytes32 capSetHash;
        bool customPredicateEnabled;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    mapping(bytes32 => DSLVersionEntry) private _versions;

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

    /// @notice Registers a Claim DSL interpreter version in the canonical registry.
    /// @dev Access: REGISTRY_ADMIN_ROLE (timelock-bound). Invariants:
    ///      interpreter MUST be non-zero (a deployed ClaimDSL contract address).
    ///      capSetHash binds the supported-operator set + WASM-predicate hooks;
    ///      mismatching capSetHash at PDA evaluation reverts at the consumer.
    ///      customPredicateEnabled = false locks PDAs to the canonical operator
    ///      set only (no WASM predicates). deprecationFlag is forcibly zeroed.
    function addDSLVersion(bytes32 dslVersionRef, DSLVersionEntry calldata entry)
        external
        onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE)
    {
        if (entry.interpreter == address(0)) revert RegistryInvalidEntry(dslVersionRef);
        DSLVersionEntry memory stored = entry;
        stored.deprecationFlag = _zeroFlag();
        _versions[dslVersionRef] = stored;
        _recordEntry(dslVersionRef, entry.effectiveBlock, entry.tombstoneBlock, entry.isCanonical);
    }

    /// @notice Returns the DSL version entry as it stood at a specific block.
    /// @dev Point-in-time reading discipline: ClaimDSL.evaluateClaim consumers
    ///      MUST read at commit_block (PDA's effective block). Prevents
    ///      mid-flight DSL upgrades from re-evaluating historical PDAs under
    ///      newer semantics. Reverts RegistryEntryUnknown /
    ///      RegistryEntryNotEffective / RegistryEntryTombstoned as appropriate.
    function getDSLVersionAt(bytes32 dslVersionRef, uint64 blockNumber) public view returns (DSLVersionEntry memory) {
        EntryMeta memory meta = _metaAt(dslVersionRef, blockNumber);
        DSLVersionEntry memory entry = _versions[dslVersionRef];
        entry.effectiveBlock = meta.effectiveBlock;
        entry.tombstoneBlock = meta.tombstoneBlock;
        entry.isCanonical = meta.isCanonical;
        entry.deprecationFlag = _deprecationFlagAt(dslVersionRef, blockNumber);
        return entry;
    }

    /// @notice Returns the current DSL version entry for the given id.
    /// @dev IBaseRegistry interface implementation. View-only. For at-commit-block
    ///      reading discipline (§1.3 NORMATIVE) use getEntryAt instead.
    function getEntry(bytes32 id) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getDSLVersionAt(id, _currentBlock()));
    }

    /// @notice Returns the DSL version entry as it was at `blockNumber`.
    /// @dev IBaseRegistry interface implementation. Implements the at-commit-block
    ///      reading discipline per §1.3 NORMATIVE — caller MUST pass commit_block.
    ///      Class-CATALOG registry (raw 32-byte ref) per
    ///      internal design record v3-registry-class-discipline.md.
    function getEntryAt(bytes32 id, uint64 blockNumber) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getDSLVersionAt(id, blockNumber));
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
