// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { DeprecationFlag } from "../lib/Structs.sol";

/// @title IBaseRegistry - shared registry surface for V3 governance + lifecycle registries
/// @notice Mirrored verbatim from S2-2 App. A lines 2402-2422. Per-registry
///         interfaces (`IPluginHashRegistry`, `IG4AuthorityRegistry`,
///         `IDSLVersionRegistry`, `IOracleRegistry`, `IOracleSchemaRegistry`,
///         `IQTSPRegistry`) inherit this interface and add a typed
///         `addX(...)` + `getXAt(...)` per-entry-type pair.
///
/// @dev DRIFT GUARD: there is NO function `getStateAtBlock` and NO
///      contract `HistoricalRegistry`. The ONLY historical-lookup surface
///      is `getEntryAt(bytes32 id, uint64 blockNumber)`. This interface
///      is the single source of truth for the registry shape; concrete
///      registries (Phase B/C) implement on top of it without
///      re-declaring the inherited error / event / function set.
///
/// @dev `getEntry` and `getEntryAt` return ABI-encoded `bytes` so the
///      base interface stays type-erased; per-registry typed accessors
///      (`getPluginAt`, `getOracleAt`, etc.) provide the typed surface.
interface IBaseRegistry {
    /// @notice Lookup id is not present in the registry.
    error RegistryEntryUnknown(bytes32 id);

    /// @notice Lookup id exists but its `effectiveBlock` is greater than
    ///         the requested `blockNumber` (i.e., not yet effective at that block).
    error RegistryEntryNotEffective(bytes32 id, uint64 blockNumber);

    /// @notice Lookup id is tombstoned at or before the requested `blockNumber`.
    error RegistryEntryTombstoned(bytes32 id, uint64 blockNumber);

    /// @notice Lookup id has an active deprecation flag.
    error RegistryEntryDeprecated(bytes32 id);

    /// @notice Disclosure summary content exceeds the per-call size limit.
    error RegistryDisclosureTooLarge(uint256 size);

    /// @notice Disclosure content does not match the expected
    ///         `disclosureCommitHash` recorded on the deprecation flag.
    error RegistryDisclosureHashMismatch(bytes32 expected, bytes32 actual);

    /// @notice Auto-clear cooldown has not elapsed; retry after `until`.
    error RegistryCooldownActive(bytes32 id, uint64 until);

    /// @notice New entry written; effective from `effectiveBlock`.
    event EntryAdded(bytes32 indexed id, uint64 effectiveBlock);

    /// @notice Entry tombstoned at `tombstoneBlock`; further reads at
    ///         `>= tombstoneBlock` revert with `RegistryEntryTombstoned`.
    event EntryTombstoned(bytes32 indexed id, uint64 tombstoneBlock);

    /// @notice Deprecation flag set on `id` with `reasonCode` and a
    ///         disclosure pointer (`disclosureCid` + `disclosureCommitHash`).
    event DeprecationFlagSet(bytes32 indexed id, uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash);

    /// @notice Disclosure summary content was published for `id`.
    event DisclosurePublished(bytes32 indexed id, bytes summaryContent);

    /// @notice Auto-clear cooldown elapsed and the deprecation flag was cleared.
    event DeprecationAutoCleared(bytes32 indexed id, uint64 cooldownUntil);

    /// @notice Read the deprecation flag for `id`. Returns the zero-value
    ///         struct when no flag is set (`deprecated == false`).
    function deprecationFlag(bytes32 id) external view returns (DeprecationFlag memory);

    /// @notice Read the current canonical entry for `id`, ABI-encoded.
    /// @dev Concrete registries provide a typed accessor (e.g.,
    ///      `getOracleAt(...) returns (OracleEntry)`) for ergonomic
    ///      consumption; the typed accessor and this `getEntry` MUST
    ///      decode to the same byte sequence.
    function getEntry(bytes32 id) external view returns (bytes memory encodedEntry);

    /// @notice Read the entry effective at `blockNumber` for `id`, ABI-encoded.
    function getEntryAt(bytes32 id, uint64 blockNumber) external view returns (bytes memory encodedEntry);

    /// @notice Publish the disclosure-summary content matching the
    ///         registered `disclosureCommitHash`.
    function publishDisclosure(bytes32 id, bytes calldata summaryContent) external;

    /// @notice Trigger the auto-clear path on `id` after the cooldown.
    function triggerAutoClear(bytes32 id) external;
}
