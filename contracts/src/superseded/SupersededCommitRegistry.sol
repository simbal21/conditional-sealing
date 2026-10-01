// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { ICealisIdentifierHelpers } from "../helpers/ICealisIdentifierHelpers.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

contract SupersededCommitRegistry is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable {
    struct SupersessionEntry {
        bytes32 oldHCommit;
        bytes32 newHCommit;
        uint16 generation;
        bytes32 lookupHash;
        bytes32 governanceRef;
        uint64 effectiveBlock;
        bool correction;
        bytes32 correctedLookupHash;
    }

    error SupersessionUnauthorized(address caller);
    error SupersessionTimelockNotExpired(bytes32 supersededCommitRef);
    error SupersessionGenerationOverflow(uint16 generation);
    error SupersessionUnknown(bytes32 supersededCommitRef);
    error SupersessionImmutable(bytes32 lookupHash);
    error SupersessionPaused(bytes32 scope);
    error SupersessionHelperMissing();

    event CommitSuperseded(
        bytes32 indexed oldHCommit, bytes32 indexed newHCommit, uint16 generation, bytes32 lookupHash
    );
    event SupersessionCorrectionRecorded(
        bytes32 indexed oldHCommit,
        bytes32 indexed rejectedLookupHash,
        bytes32 indexed correctedLookupHash,
        bytes32 governanceRef
    );

    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;
    bytes32 public constant PAUSER_ROLE = Roles.PAUSER_ROLE;
    bytes32 public constant REKEY_GOVERNANCE_ROLE = Roles.REKEY_GOVERNANCE_ROLE;
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    ICealisIdentifierHelpers public identifierHelpers;
    mapping(bytes32 => SupersessionEntry[]) private _lineage;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address helper) external initializer {
        if (helper == address(0)) {
            revert SupersessionHelperMissing();
        }
        identifierHelpers = ICealisIdentifierHelpers(helper);
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
        _grantRole(Roles.REKEY_GOVERNANCE_ROLE, timelock);
    }

    /// @notice Records a commit-supersession (re-key) lineage entry.
    /// @dev REKEY_GOVERNANCE_ROLE only (`_requireRekeyGovernance`). Used by the
    ///      S2-1 §15 re-key ceremony (P21) to track that newHCommit supersedes
    ///      oldHCommit at the given generation. Generation is uint16 with overflow
    ///      revert (SupersessionGenerationOverflow). lookupHash is computed via
    ///      identifierHelpers.computeSupersededCommitLookup for cross-version
    ///      lookup uniqueness. Append-only.
    /// @param oldHCommit hCommit being superseded.
    /// @param newHCommit replacement hCommit at the new generation.
    /// @param generation generation counter for this lineage (bounded uint16).
    /// @param governanceRef hash of the off-chain governance decision.
    function recordSupersession(bytes32 oldHCommit, bytes32 newHCommit, uint16 generation, bytes32 governanceRef)
        external
    {
        _requireRekeyGovernance();
        _requireNotPaused(GLOBAL_SCOPE);
        if (generation == type(uint16).max) {
            revert SupersessionGenerationOverflow(generation);
        }
        bytes32 lookupHash = identifierHelpers.computeSupersededCommitLookup(oldHCommit, generation);
        SupersessionEntry memory entry = SupersessionEntry({
            oldHCommit: oldHCommit,
            newHCommit: newHCommit,
            generation: generation,
            lookupHash: lookupHash,
            governanceRef: governanceRef,
            effectiveBlock: uint64(block.number),
            correction: false,
            correctedLookupHash: bytes32(0)
        });
        _lineage[oldHCommit].push(entry);
        emit CommitSuperseded(oldHCommit, newHCommit, generation, lookupHash);
    }

    /// @notice Records a correction to a previously-recorded supersession lookup hash.
    /// @dev REKEY_GOVERNANCE_ROLE only. Used when a prior recordSupersession entry's
    ///      lookupHash is found to be incorrect (e.g., off-chain bookkeeping error
    ///      discovered post-fact). Append-only: writes a NEW lineage entry with
    ///      correction=true rather than mutating the prior entry. successorOf
    ///      skips correction entries (newHCommit=0); lineageCheckpoint can still
    ///      reach them for auditor visibility. Reverts if no prior lineage exists.
    function recordSupersessionCorrection(
        bytes32 oldHCommit,
        bytes32 rejectedLookupHash,
        bytes32 correctedLookupHash,
        bytes32 governanceRef
    ) external {
        _requireRekeyGovernance();
        _requireNotPaused(GLOBAL_SCOPE);
        if (_lineage[oldHCommit].length == 0) {
            revert SupersessionUnknown(oldHCommit);
        }
        SupersessionEntry memory entry = SupersessionEntry({
            oldHCommit: oldHCommit,
            newHCommit: bytes32(0),
            generation: _lineage[oldHCommit][_lineage[oldHCommit].length - 1].generation,
            lookupHash: rejectedLookupHash,
            governanceRef: governanceRef,
            effectiveBlock: uint64(block.number),
            correction: true,
            correctedLookupHash: correctedLookupHash
        });
        _lineage[oldHCommit].push(entry);
        emit SupersessionCorrectionRecorded(oldHCommit, rejectedLookupHash, correctedLookupHash, governanceRef);
    }

    function successorOf(bytes32 oldHCommit) external view returns (bytes32 newHCommit, uint16 generation) {
        return _successorOfAt(oldHCommit, uint64(block.number));
    }

    function successorOfAt(bytes32 oldHCommit, uint64 blockNumber)
        external
        view
        returns (bytes32 newHCommit, uint16 generation)
    {
        return _successorOfAt(oldHCommit, blockNumber);
    }

    function lineageCheckpoint(bytes32 oldHCommit, uint64 blockNumber)
        external
        view
        returns (SupersessionEntry memory entry)
    {
        SupersessionEntry[] storage entries = _lineage[oldHCommit];
        for (uint256 i = entries.length; i > 0; --i) {
            if (entries[i - 1].effectiveBlock <= blockNumber) {
                return entries[i - 1];
            }
        }
        revert SupersessionUnknown(oldHCommit);
    }

    function lineageLength(bytes32 oldHCommit) external view returns (uint256) {
        return _lineage[oldHCommit].length;
    }

    function _successorOfAt(bytes32 oldHCommit, uint64 blockNumber)
        internal
        view
        returns (bytes32 newHCommit, uint16 generation)
    {
        SupersessionEntry[] storage entries = _lineage[oldHCommit];
        for (uint256 i = entries.length; i > 0; --i) {
            SupersessionEntry storage entry = entries[i - 1];
            if (entry.effectiveBlock <= blockNumber && !entry.correction) {
                return (entry.newHCommit, entry.generation);
            }
        }
        revert SupersessionUnknown(oldHCommit);
    }

    function _requireRekeyGovernance() internal view {
        if (!hasRole(Roles.REKEY_GOVERNANCE_ROLE, msg.sender)) {
            revert SupersessionUnauthorized(msg.sender);
        }
    }

    function _requireNotPaused(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert SupersessionPaused(scope);
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
