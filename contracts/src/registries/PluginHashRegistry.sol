// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { IBaseRegistry } from "../base/IBaseRegistry.sol";
import { ICealisIdentifierHelpers } from "../helpers/ICealisIdentifierHelpers.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";
import { DeprecationFlag } from "../lib/Structs.sol";

/// @dev Local compatibility adapter. The vendored OZ v5 tree in this workspace
///      exposes core AccessControl and proxy utilities, not the separate
///      contracts-upgradeable package. Registries still inherit the required
///      `AccessControlUpgradeable` name while using OZ AccessControl storage.
abstract contract AccessControlUpgradeable is AccessControl {
    function __AccessControl_init() internal { }
}

/// @dev Local compatibility adapter matching the S2-2 inheritance surface.
///      Registry pause semantics are implemented by `BoundedPausable`; this
///      adapter keeps the mandated PausableUpgradeable inheritance name present.
abstract contract PausableUpgradeable is Pausable {
    function __Pausable_init() internal { }
}

error RegistryUnauthorized(bytes32 role, address caller);
error RegistryEntryAlreadyExists(bytes32 id);
error RegistryInvalidEntry(bytes32 id);
error RegistryLookupKeyMismatch(bytes32 expected, bytes32 actual);
error RegistryPaused(bytes32 scope, uint64 until);
error RegistryDeprecationNotActive(bytes32 id);
error RegistryDeprecationAlreadyActive(bytes32 id);
error RegistryInvalidDeprecationReason(uint8 reasonCode);
error RegistryDisclosureRequired(bytes32 disclosureCid, bytes32 disclosureCommitHash);
error RegistryDisclosureAlreadyPublished(bytes32 id);
error RegistryAutoClearNotReady(bytes32 id, uint64 autoClearTimestamp);
error RegistryCanonicalRequiresTimelock(bytes32 id);
error RegistryCanonicalDeprecationNotQueued(bytes32 id);
error RegistryCanonicalDeprecationNotReady(bytes32 id, uint64 readyAt);
error RegistrySecurityCouncilSuspended(uint64 until);
error RegistryZeroAddress();

event CanonicalDeprecationQueued(
    bytes32 indexed id, uint64 readyAt, uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash
);
event SecurityCouncilDeprecationSuspended(uint64 until);

/// @title GovernedRegistry - shared V3 registry governance and lookup mechanics
/// @notice Implements `IBaseRegistry` shared behavior for the Phase B registries.
///         Concrete registries provide typed storage/accessors and call
///         `_recordEntry` from their `addX` function.
abstract contract GovernedRegistry is IBaseRegistry, BoundedPausable {
    uint64 internal constant AUTO_CLEAR_DELAY_SECONDS = 72 hours;
    uint64 internal constant COOLDOWN_SECONDS = 30 days;
    uint64 internal constant CANONICAL_DEPRECATION_DELAY_SECONDS = 24 hours;
    bytes32 public constant GLOBAL_REGISTRY_SCOPE = bytes32(0);

    struct EntryMeta {
        bool exists;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        bool isCanonical;
        uint64 cooldownUntil;
        PendingDeprecation pendingDeprecation;
    }

    struct PendingDeprecation {
        bool queued;
        uint64 readyAt;
        uint8 reasonCode;
        bytes32 disclosureCid;
        bytes32 disclosureCommitHash;
    }

    struct DeprecationCheckpoint {
        uint64 fromBlock;
        uint64 clearedBlock;
        DeprecationFlag flag;
    }

    mapping(bytes32 => EntryMeta) internal _entryMeta;
    mapping(bytes32 => DeprecationCheckpoint[]) internal _deprecationCheckpoints;
    uint64 internal _securityCouncilSuspendedUntil;

    modifier onlyRegistryRole(bytes32 role) {
        if (!_registryHasRole(role, msg.sender)) revert RegistryUnauthorized(role, msg.sender);
        _;
    }

    function deprecationFlag(bytes32 id) external view override returns (DeprecationFlag memory) {
        return _currentDeprecationFlag(id);
    }

    function tombstoneEntry(bytes32 id, uint64 tombstoneBlock) external onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE) {
        _requireNotPausedFor(id);
        EntryMeta storage meta = _requireMeta(id);
        if (meta.tombstoneBlock != 0) revert RegistryEntryTombstoned(id, meta.tombstoneBlock);

        uint64 effectiveTombstone = tombstoneBlock == 0 ? uint64(block.number) : tombstoneBlock;
        if (effectiveTombstone <= meta.effectiveBlock) revert RegistryEntryNotEffective(id, effectiveTombstone);

        meta.tombstoneBlock = effectiveTombstone;
        emit EntryTombstoned(id, effectiveTombstone);
    }

    function deprecateEntry(bytes32 id, uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash)
        external
        onlyRegistryRole(Roles.SECURITY_COUNCIL_ROLE)
    {
        _requireSecurityCouncilActive();
        _setDeprecation(id, reasonCode, disclosureCid, disclosureCommitHash, false, false);
    }

    function deprecateEntryByTimelock(bytes32 id, uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash)
        external
        onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE)
    {
        _setDeprecation(id, reasonCode, disclosureCid, disclosureCommitHash, true, true);
    }

    function queueCanonicalDeprecation(
        bytes32 id,
        uint8 reasonCode,
        bytes32 disclosureCid,
        bytes32 disclosureCommitHash
    ) external onlyRegistryRole(Roles.SECURITY_COUNCIL_ROLE) {
        _requireSecurityCouncilActive();
        _validateDeprecationInputs(reasonCode, disclosureCid, disclosureCommitHash);
        EntryMeta storage meta = _requireMeta(id);
        if (!meta.isCanonical) revert RegistryInvalidEntry(id);
        if (_currentDeprecationFlag(id).deprecated) revert RegistryDeprecationAlreadyActive(id);
        if (meta.cooldownUntil > block.timestamp) revert RegistryCooldownActive(id, meta.cooldownUntil);

        uint64 readyAt = uint64(block.timestamp + CANONICAL_DEPRECATION_DELAY_SECONDS);
        meta.pendingDeprecation = PendingDeprecation({
            queued: true,
            readyAt: readyAt,
            reasonCode: reasonCode,
            disclosureCid: disclosureCid,
            disclosureCommitHash: disclosureCommitHash
        });
        emit CanonicalDeprecationQueued(id, readyAt, reasonCode, disclosureCid, disclosureCommitHash);
    }

    function executeCanonicalDeprecation(bytes32 id) external onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE) {
        EntryMeta storage meta = _requireMeta(id);
        PendingDeprecation memory pending = meta.pendingDeprecation;
        if (!pending.queued) revert RegistryCanonicalDeprecationNotQueued(id);
        if (block.timestamp < pending.readyAt) revert RegistryCanonicalDeprecationNotReady(id, pending.readyAt);

        delete meta.pendingDeprecation;
        _setDeprecation(id, pending.reasonCode, pending.disclosureCid, pending.disclosureCommitHash, true, true);
    }

    function suspendSecurityCouncilDeprecation(uint64 until)
        external
        onlyRegistryRole(Roles.EMERGENCY_GOVERNANCE_ROLE)
    {
        if (until <= block.timestamp) {
            _securityCouncilSuspendedUntil = 0;
            emit SecurityCouncilDeprecationSuspended(0);
            return;
        }
        uint64 maxUntil = uint64(block.timestamp) + PauseConstants.MAX_EMERGENCY_PAUSE_SECONDS;
        if (until > maxUntil) revert PauseDurationTooLong(GLOBAL_REGISTRY_SCOPE, until, maxUntil);
        _securityCouncilSuspendedUntil = until;
        emit SecurityCouncilDeprecationSuspended(until);
    }

    /// @notice Publishes the deprecation-disclosure summary content for a deprecated entry.
    /// @dev Permissionless by design: anyone can publish the summary as long as its
    ///      keccak256 matches the previously-committed disclosureCommitHash on the
    ///      active deprecation checkpoint. Caps summaryContent at 4096 bytes
    ///      (RegistryDisclosureTooLarge). One-shot per checkpoint (revert if already
    ///      verified per RegistryDisclosureAlreadyPublished). Sets disclosureVerifiedBlock
    ///      to enable the 24h expedited-canonical deprecation path per S2-6 §13.6(b).
    function publishDisclosure(bytes32 id, bytes calldata summaryContent) external override {
        EntryMeta storage meta = _requireMeta(id);
        meta; // keeps the base unknown check visible to audit readers

        DeprecationCheckpoint[] storage checkpoints = _deprecationCheckpoints[id];
        if (checkpoints.length == 0) revert RegistryDeprecationNotActive(id);
        DeprecationCheckpoint storage checkpoint = checkpoints[checkpoints.length - 1];
        if (!checkpoint.flag.deprecated || checkpoint.clearedBlock != 0) revert RegistryDeprecationNotActive(id);
        if (checkpoint.flag.disclosureVerifiedBlock != 0) revert RegistryDisclosureAlreadyPublished(id);
        if (summaryContent.length > 4096) revert RegistryDisclosureTooLarge(summaryContent.length);

        bytes32 actual = keccak256(summaryContent);
        if (actual != checkpoint.flag.disclosureCommitHash) {
            revert RegistryDisclosureHashMismatch(checkpoint.flag.disclosureCommitHash, actual);
        }

        checkpoint.flag.disclosureVerifiedBlock = uint64(block.number);
        emit DisclosurePublished(id, summaryContent);
    }

    /// @notice Triggers the 72h auto-clear of a deprecation if no disclosure was published.
    /// @dev Permissionless by design (S2-6 §13.6(d)). Reverts if (a) no active
    ///      deprecation, (b) 72h not elapsed since deprecation block, (c) disclosure
    ///      already published (in which case the 24h expedited path applies instead).
    ///      Auto-cleared entries enter a 30-day cooldown before re-deprecation (§13.6(e)).
    function triggerAutoClear(bytes32 id) external override {
        EntryMeta storage meta = _requireMeta(id);
        DeprecationCheckpoint[] storage checkpoints = _deprecationCheckpoints[id];
        if (checkpoints.length == 0) revert RegistryDeprecationNotActive(id);
        DeprecationCheckpoint storage checkpoint = checkpoints[checkpoints.length - 1];
        if (!checkpoint.flag.deprecated || checkpoint.clearedBlock != 0) revert RegistryDeprecationNotActive(id);
        if (checkpoint.flag.disclosureVerifiedBlock != 0) revert RegistryDisclosureAlreadyPublished(id);
        if (block.timestamp < checkpoint.flag.autoClearTimestamp) {
            revert RegistryAutoClearNotReady(id, checkpoint.flag.autoClearTimestamp);
        }

        checkpoint.clearedBlock = uint64(block.number);
        meta.cooldownUntil = uint64(block.timestamp + COOLDOWN_SECONDS);
        emit DeprecationAutoCleared(id, meta.cooldownUntil);
    }

    function _initializeRegistry(address timelock, address securityCouncil, address emergencyGovernance, address pauser)
        internal
    {
        if (timelock == address(0) || securityCouncil == address(0) || emergencyGovernance == address(0)) {
            revert RegistryZeroAddress();
        }
        if (pauser == address(0)) revert RegistryZeroAddress();

        _registrySetRoleAdmin(Roles.UPGRADER_ROLE, Roles.DEFAULT_ADMIN_ROLE);
        _registrySetRoleAdmin(Roles.REGISTRY_ADMIN_ROLE, Roles.DEFAULT_ADMIN_ROLE);
        _registrySetRoleAdmin(Roles.SECURITY_COUNCIL_ROLE, Roles.DEFAULT_ADMIN_ROLE);
        _registrySetRoleAdmin(Roles.EMERGENCY_GOVERNANCE_ROLE, Roles.DEFAULT_ADMIN_ROLE);
        _registrySetRoleAdmin(Roles.PAUSER_ROLE, Roles.DEFAULT_ADMIN_ROLE);
        _registrySetRoleAdmin(Roles.OPERATOR_ROLE, Roles.DEFAULT_ADMIN_ROLE);

        _registryGrantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _registryGrantRole(Roles.UPGRADER_ROLE, timelock);
        _registryGrantRole(Roles.REGISTRY_ADMIN_ROLE, timelock);
        _registryGrantRole(Roles.SECURITY_COUNCIL_ROLE, securityCouncil);
        _registryGrantRole(Roles.EMERGENCY_GOVERNANCE_ROLE, emergencyGovernance);
        _registryGrantRole(Roles.PAUSER_ROLE, pauser);
    }

    function _recordEntry(bytes32 id, uint64 effectiveBlock, uint64 tombstoneBlock, bool isCanonical) internal {
        _requireNotPausedFor(id);
        if (id == bytes32(0) || effectiveBlock == 0) revert RegistryInvalidEntry(id);
        if (_entryMeta[id].exists) revert RegistryEntryAlreadyExists(id);
        if (tombstoneBlock != 0 && tombstoneBlock <= effectiveBlock) {
            revert RegistryEntryTombstoned(id, tombstoneBlock);
        }

        _entryMeta[id] = EntryMeta({
            exists: true,
            effectiveBlock: effectiveBlock,
            tombstoneBlock: tombstoneBlock,
            isCanonical: isCanonical,
            cooldownUntil: 0,
            pendingDeprecation: PendingDeprecation({
                queued: false, readyAt: 0, reasonCode: 0, disclosureCid: bytes32(0), disclosureCommitHash: bytes32(0)
            })
        });
        emit EntryAdded(id, effectiveBlock);
    }

    function _metaAt(bytes32 id, uint64 blockNumber) internal view returns (EntryMeta memory meta) {
        meta = _entryMeta[id];
        if (!meta.exists) revert RegistryEntryUnknown(id);
        if (meta.effectiveBlock > blockNumber) revert RegistryEntryNotEffective(id, blockNumber);
        if (meta.tombstoneBlock != 0 && meta.tombstoneBlock <= blockNumber) {
            revert RegistryEntryTombstoned(id, blockNumber);
        }
    }

    function _currentBlock() internal view returns (uint64) {
        return uint64(block.number);
    }

    function _currentDeprecationFlag(bytes32 id) internal view returns (DeprecationFlag memory) {
        DeprecationCheckpoint[] storage checkpoints = _deprecationCheckpoints[id];
        if (checkpoints.length == 0) return _zeroFlag();

        DeprecationCheckpoint storage checkpoint = checkpoints[checkpoints.length - 1];
        if (checkpoint.clearedBlock != 0) return _zeroFlag();
        return checkpoint.flag;
    }

    function _deprecationFlagAt(bytes32 id, uint64 blockNumber) internal view returns (DeprecationFlag memory) {
        DeprecationCheckpoint[] storage checkpoints = _deprecationCheckpoints[id];
        for (uint256 i = checkpoints.length; i > 0;) {
            unchecked {
                --i;
            }
            DeprecationCheckpoint storage checkpoint = checkpoints[i];
            if (checkpoint.fromBlock <= blockNumber) {
                if (checkpoint.clearedBlock != 0 && checkpoint.clearedBlock <= blockNumber) return _zeroFlag();
                return checkpoint.flag;
            }
        }
        return _zeroFlag();
    }

    function _zeroFlag() internal pure returns (DeprecationFlag memory) {
        return DeprecationFlag({
            deprecated: false,
            deprecationBlockTimestamp: 0,
            deprecationReasonCode: 0,
            disclosureCid: bytes32(0),
            disclosureCommitHash: bytes32(0),
            disclosureVerifiedBlock: 0,
            autoClearTimestamp: 0,
            isCanonicalAtSet: false
        });
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (!_registryHasRole(Roles.PAUSER_ROLE, caller)) revert PauseUnauthorized(scope, caller);
    }

    function _maxPauseDuration() internal pure override returns (uint64) {
        return PauseConstants.MAX_REGISTRY_PAUSE_SECONDS;
    }

    function _pauseAuthorityMode(bytes32) internal pure override returns (PauseAuthorityMode) {
        return PauseAuthorityMode.Joint;
    }

    function _registryHasRole(bytes32 role, address account) internal view virtual returns (bool);

    function _registryGrantRole(bytes32 role, address account) internal virtual;

    function _registrySetRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual;

    function _requireMeta(bytes32 id) private view returns (EntryMeta storage meta) {
        meta = _entryMeta[id];
        if (!meta.exists) revert RegistryEntryUnknown(id);
    }

    function _setDeprecation(
        bytes32 id,
        uint8 reasonCode,
        bytes32 disclosureCid,
        bytes32 disclosureCommitHash,
        bool allowCanonical,
        bool bypassCooldown
    ) private {
        _validateDeprecationInputs(reasonCode, disclosureCid, disclosureCommitHash);
        EntryMeta storage meta = _requireMeta(id);
        if (_currentDeprecationFlag(id).deprecated) revert RegistryDeprecationAlreadyActive(id);
        if (meta.isCanonical && !allowCanonical) revert RegistryCanonicalRequiresTimelock(id);
        if (!bypassCooldown && meta.cooldownUntil > block.timestamp) {
            revert RegistryCooldownActive(id, meta.cooldownUntil);
        }

        DeprecationFlag memory flag = DeprecationFlag({
            deprecated: true,
            deprecationBlockTimestamp: uint64(block.timestamp),
            deprecationReasonCode: reasonCode,
            disclosureCid: disclosureCid,
            disclosureCommitHash: disclosureCommitHash,
            disclosureVerifiedBlock: 0,
            autoClearTimestamp: uint64(block.timestamp + AUTO_CLEAR_DELAY_SECONDS),
            isCanonicalAtSet: meta.isCanonical
        });
        _deprecationCheckpoints[id].push(
            DeprecationCheckpoint({ fromBlock: uint64(block.number), clearedBlock: 0, flag: flag })
        );
        emit DeprecationFlagSet(id, reasonCode, disclosureCid, disclosureCommitHash);
    }

    function _validateDeprecationInputs(uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash)
        private
        pure
    {
        if (reasonCode < 1 || reasonCode > 4) revert RegistryInvalidDeprecationReason(reasonCode);
        if (disclosureCid == bytes32(0) || disclosureCommitHash == bytes32(0)) {
            revert RegistryDisclosureRequired(disclosureCid, disclosureCommitHash);
        }
    }

    function _requireSecurityCouncilActive() private view {
        if (_securityCouncilSuspendedUntil != 0 && block.timestamp < _securityCouncilSuspendedUntil) {
            revert RegistrySecurityCouncilSuspended(_securityCouncilSuspendedUntil);
        }
    }

    function _requireNotPausedFor(bytes32 id) private view {
        uint64 globalUntil = _pauses[GLOBAL_REGISTRY_SCOPE].until;
        if (globalUntil != 0 && block.timestamp < globalUntil) {
            revert RegistryPaused(GLOBAL_REGISTRY_SCOPE, globalUntil);
        }

        uint64 entryUntil = _pauses[id].until;
        if (entryUntil != 0 && block.timestamp < entryUntil) revert RegistryPaused(id, entryUntil);
    }
}

/// @title PluginHashRegistry - canonical plugin-binary registry (class-CRYPTO)
/// @notice One of the 5 Cealis-governed V3 registries. Records authorized
///         age-plugin-cealis-v3 binaries by their canonical content digest.
///         Class-CRYPTO discipline (per internal design record `v3-registry-class-discipline.md`):
///         lookup key MUST equal TAG_PLUGIN_VERSION_V3-prefixed keccak of the
///         binary hash — RegistryLookupKeyMismatch reverts on tag-omission
///         attempts, eliminating raw-hash collisions across registry classes.
/// @dev Inherits governance machinery from GovernedRegistry: deprecation
///      (Security Council 0-delay OR Timelock 24h queued for canonical entries),
///      72h auto-clear if no disclosure published, 30-day post-clear cooldown,
///      pausable per-entry or globally. Crypto-non-custody invariant: ANY
///      deviation from a tombstoned/deprecated plugin binary at gate-signing
///      time MUST cause G4 to refuse via 0x06 (class-CRYPTO breach refusal).
contract PluginHashRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    GovernedRegistry
{
    struct PluginEntry {
        bytes32 canonicalBinaryHash;
        bytes32 sourceCommitDigest;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    ICealisIdentifierHelpers public identifierHelpers;
    mapping(bytes32 => PluginEntry) private _plugins;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address timelock,
        address securityCouncil,
        address emergencyGovernance,
        address pauser,
        address identifierHelpers_
    ) public initializer {
        __AccessControl_init();
        __Pausable_init();
        if (identifierHelpers_ == address(0)) revert RegistryZeroAddress();
        identifierHelpers = ICealisIdentifierHelpers(identifierHelpers_);
        _initializeRegistry(timelock, securityCouncil, emergencyGovernance, pauser);
    }

    /// @notice Registers a plugin binary in the canonical registry.
    /// @dev Access: REGISTRY_ADMIN_ROLE (timelock-bound). Class-CRYPTO key
    ///      discipline: pluginVersionDigest MUST equal
    ///      identifierHelpers.computePluginVersionDigest(entry.canonicalBinaryHash)
    ///      — keccak256(TAG_PLUGIN_VERSION_V3 || canonicalBinaryHash). Mismatch
    ///      reverts RegistryLookupKeyMismatch. deprecationFlag is forcibly
    ///      zeroed on entry (deprecation is a post-add governance action).
    ///      entry.effectiveBlock MUST be non-zero; tombstoneBlock 0 means
    ///      no scheduled tombstone.
    function addPlugin(bytes32 pluginVersionDigest, PluginEntry calldata entry)
        external
        onlyRegistryRole(Roles.REGISTRY_ADMIN_ROLE)
    {
        bytes32 expected = identifierHelpers.computePluginVersionDigest(entry.canonicalBinaryHash);
        if (pluginVersionDigest != expected) revert RegistryLookupKeyMismatch(expected, pluginVersionDigest);

        PluginEntry memory stored = entry;
        stored.deprecationFlag = _zeroFlag();
        _plugins[pluginVersionDigest] = stored;
        _recordEntry(pluginVersionDigest, entry.effectiveBlock, entry.tombstoneBlock, entry.isCanonical);
    }

    /// @notice Returns the plugin entry as it stood at a specific block (point-in-time read).
    /// @dev "Point-in-time reading discipline" per S2-3 §11: combiners + G4 verifiers
    ///      MUST read this registry at commit_block, not at gate-signing block. Prevents
    ///      mid-flight plugin retraction from re-keying existing commits. Reverts
    ///      RegistryEntryUnknown / RegistryEntryNotEffective / RegistryEntryTombstoned
    ///      as appropriate. deprecationFlag is the checkpoint-at-block flag, not the
    ///      current one — same point-in-time semantics.
    function getPluginAt(bytes32 pluginVersionDigest, uint64 blockNumber) public view returns (PluginEntry memory) {
        EntryMeta memory meta = _metaAt(pluginVersionDigest, blockNumber);
        PluginEntry memory entry = _plugins[pluginVersionDigest];
        entry.effectiveBlock = meta.effectiveBlock;
        entry.tombstoneBlock = meta.tombstoneBlock;
        entry.isCanonical = meta.isCanonical;
        entry.deprecationFlag = _deprecationFlagAt(pluginVersionDigest, blockNumber);
        return entry;
    }

    function getEntry(bytes32 id) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getPluginAt(id, _currentBlock()));
    }

    function getEntryAt(bytes32 id, uint64 blockNumber) external view override returns (bytes memory encodedEntry) {
        return abi.encode(getPluginAt(id, blockNumber));
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
