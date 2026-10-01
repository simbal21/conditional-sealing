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

/// @title QTSPRegistry - Qualified Trust Service Provider registry (class-CATALOG)
/// @notice One of the 5 Cealis-governed V3 registries. Records EU-regulated
///         Qualified Trust Service Providers (per eIDAS Regulation 910/2014)
///         whose qualified-electronic-signatures may be referenced in PDAs
///         requiring legal-effect anchoring (e.g., notarial release, lawyer-
///         attested testament, regulator-acknowledged disclosure). Underpins
///         §371a ZPO admissibility for the legal-evidence reveal path.
/// @dev Class-CATALOG discipline (per internal design record `v3-registry-class-discipline.md`):
///      qtspProviderRef is a CONFIGURED raw 32-byte ref — domain separation
///      comes from upstream TAG_AAD_V3 / pda_root wrapping. qtspRootPubkeyHash
///      binds the QTSP's root certificate fingerprint; jurisdiction is the
///      2-byte ISO 3166-1 alpha-2 country code (EU member states only at
///      MVP); eidasStatusUrlHash binds the EU Trusted List URL where this
///      QTSP's "active" status is published. PDAs gating on
///      legal_effect_expected==true MUST reference a registered QTSP at
///      commit_block.
contract QTSPRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    GovernedRegistry
{
    struct QTSPEntry {
        bytes32 qtspRootPubkeyHash;
        bytes2 jurisdiction;
        bytes32 eidasStatusUrlHash;
        bytes32 metadataHash;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    mapping(bytes32 => QTSPEntry) private _qtsps;

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

    /// @notice Registers a Qualified Trust Service Provider in the canonical registry.
    /// @dev Access: REGISTRY_ADMIN_ROLE (timelock-bound). Invariant:
    ///      qtspRootPubkeyHash MUST be non-zero (binds the QTSP's root
    ///      certificate fingerprint). Off-chain pre-flight: admin SHOULD
    ///      verify the QTSP's "active" status on the EU Trusted List
    ///      identified by eidasStatusUrlHash before adding. deprecationFlag
    ///      is forcibly zeroed at add-time.
    function addQTSP(bytes32 qtspProviderRef, QTSPEntry calldata entry)
        external
        onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE)
    {
        if (entry.qtspRootPubkeyHash == bytes32(0)) revert RegistryInvalidEntry(qtspProviderRef);
        QTSPEntry memory stored = entry;
        stored.deprecationFlag = _zeroFlag();
        _qtsps[qtspProviderRef] = stored;
        _recordEntry(qtspProviderRef, entry.effectiveBlock, entry.tombstoneBlock, entry.isCanonical);
    }

    /// @notice Returns the QTSP entry as it stood at a specific block.
    /// @dev Point-in-time reading discipline: §371a ZPO admissibility chain
    ///      MUST read at commit_block of the PDA. Prevents mid-flight QTSP
    ///      delisting from invalidating in-flight legal-evidence reveals
    ///      committed under the prior valid registration. Reverts
    ///      RegistryEntryUnknown / RegistryEntryNotEffective /
    ///      RegistryEntryTombstoned as appropriate.
    function getQTSPAt(bytes32 qtspProviderRef, uint64 blockNumber) public view returns (QTSPEntry memory) {
        EntryMeta memory meta = _metaAt(qtspProviderRef, blockNumber);
        QTSPEntry memory entry = _qtsps[qtspProviderRef];
        entry.effectiveBlock = meta.effectiveBlock;
        entry.tombstoneBlock = meta.tombstoneBlock;
        entry.isCanonical = meta.isCanonical;
        entry.deprecationFlag = _deprecationFlagAt(qtspProviderRef, blockNumber);
        return entry;
    }

    /// @notice Returns the current QTSP entry for the given id.
    /// @dev Qualified Trust Service Provider registry per eIDAS. View-only; for
    ///      at-commit-block discipline use getEntryAt.
    function getEntry(bytes32 id) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getQTSPAt(id, _currentBlock()));
    }

    /// @notice Returns the QTSP entry as it was at `blockNumber`.
    /// @dev §1.3 NORMATIVE at-commit-block discipline. Class-CATALOG (raw 32-byte
    ///      ref) per v3-registry-class-discipline.md — domain separation via
    ///      upstream TAG_AAD_V3 / pda_root wrapping. Reads pair with §371a ZPO
    ///      admissibility chain (legal-evidence path).
    function getEntryAt(bytes32 id, uint64 blockNumber) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getQTSPAt(id, blockNumber));
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
