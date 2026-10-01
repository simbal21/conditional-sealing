// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { GateKind, PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

/// @title GateRecipientPubkeyRegistry - per-gate KEM pubkey publication
/// @notice Holds gate-recipient KEM public keys for σ-wrap targeting. Combiners
///         and partner SDKs reads here to discover which pubkey each gate
///         (Lit V3, G3 drand, G4, Conditional) is using for a given commit.
///         Hybrid PQ KEM (X25519 + ML-KEM-768) keys per S2-3 §11.
/// @dev Dual-mode access control split by gate kind:
///        - Drand (GateKind.Drand): long-lived committee KEM key. Published via
///          REGISTRY_ADMIN_ROLE (timelock-bound). perCommitEphemeral=false.
///          Reflects drand's lack of per-commit ephemeral primitive — risk
///          mitigated via Shamir-share-only-leak design.
///        - Lit V3 / G4 / Conditional: per-commit ephemeral KEM keys. Published
///          via GATE_PUBKEY_PUBLISHER_ROLE. perCommitEphemeral=true mandatory.
///          This is the crypto-non-custody guarantee: a key that exists only
///          for one commit can't be reused to retroactively decrypt others.
///      Storage is append-only — re-publishing via publishPubkey adds a new
///      history entry. getPubkeyAt enforces "at-commit-block reading discipline"
///      (S2-3 §11): combiners MUST read pubkey-as-of-block(commit) so mid-commit
///      rotations cannot replay an old commit under a fresh KEM key.
contract GateRecipientPubkeyRegistry is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable {
    struct GateRecipientPubkeyEntry {
        bytes32 authorizationId;
        uint8 gateKind;
        uint16 conditionalRecipientIndex;
        bytes kemPubkey;
        bytes32 attestationRef;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        bool perCommitEphemeral;
    }

    error GatePubkeyUnknown(bytes32 authorizationId, uint8 gateKind, uint16 conditionalRecipientIndex);
    error GatePubkeyMismatch(bytes32 authorizationId, uint8 gateKind);
    error GatePubkeyTimelockRequired(uint8 gateKind);
    error GatePubkeyPaused(bytes32 scope);
    // F-6: raised when a publish supplies an effectiveBlock earlier than the current block.
    error GatePubkeyEffectiveBlockBackdated(uint64 effectiveBlock, uint64 currentBlock);

    event GateRecipientPubkeyPublished(
        bytes32 indexed authorizationId,
        uint8 indexed gateKind,
        uint16 indexed conditionalRecipientIndex,
        bytes32 attestationRef
    );

    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;
    bytes32 public constant PAUSER_ROLE = Roles.PAUSER_ROLE;
    bytes32 public constant REGISTRY_ADMIN_ROLE = Roles.REGISTRY_ADMIN_ROLE;
    bytes32 public constant GATE_PUBKEY_PUBLISHER_ROLE = Roles.GATE_PUBKEY_PUBLISHER_ROLE;

    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    mapping(bytes32 => GateRecipientPubkeyEntry[]) private _entriesByKey;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
        _grantRole(Roles.REGISTRY_ADMIN_ROLE, timelock);
    }

    /// @notice Publishes a per-commit gate-recipient public key.
    /// @dev Dual-mode access control per gate kind:
    ///      - Drand (long-lived committee KEM key): REGISTRY_ADMIN_ROLE (timelock-bound),
    ///        perCommitEphemeral MUST be false. Reflects drand's lack of per-commit
    ///        ephemeral KEM primitive (mitigated via Shamir-share-only-leak).
    ///      - Lit V3 / G4 / Conditional: GATE_PUBKEY_PUBLISHER_ROLE, perCommitEphemeral
    ///        MUST be true. Per-commit ephemeral pubkeys for cryptographic non-custody.
    ///      Append-only via _entriesByKey push. Reads use getPubkeyAt for at-commit-block
    ///      reading discipline.
    function publishPubkey(GateRecipientPubkeyEntry calldata entry) external {
        _requireNotPaused(GLOBAL_SCOPE);

        if (entry.gateKind == uint8(GateKind.Drand)) {
            if (entry.perCommitEphemeral || !hasRole(Roles.REGISTRY_ADMIN_ROLE, msg.sender)) {
                revert GatePubkeyTimelockRequired(entry.gateKind);
            }
        } else if (!entry.perCommitEphemeral || !hasRole(Roles.GATE_PUBKEY_PUBLISHER_ROLE, msg.sender)) {
            revert GatePubkeyTimelockRequired(entry.gateKind);
        }

        GateRecipientPubkeyEntry memory stored = entry;
        if (stored.effectiveBlock == 0) {
            stored.effectiveBlock = uint64(block.number);
        } else if (stored.effectiveBlock < uint64(block.number)) {
            // F-6: a caller-supplied effectiveBlock in the PAST would let a privileged
            // publisher backdate a new pubkey so getPubkeyAt(commitBlock) shadows the
            // legitimate as-of-commit key for an already-committed authorization,
            // breaking the at-commit-block reading discipline. Forward-dating (>= now)
            // stays allowed for scheduled rotations.
            revert GatePubkeyEffectiveBlockBackdated(stored.effectiveBlock, uint64(block.number));
        }

        _entriesByKey[_key(entry.authorizationId, entry.gateKind, entry.conditionalRecipientIndex)].push(stored);
        emit GateRecipientPubkeyPublished(
            entry.authorizationId, entry.gateKind, entry.conditionalRecipientIndex, entry.attestationRef
        );
    }

    /// @notice Reads the gate-recipient pubkey effective at a given block number.
    /// @dev "At-commit-block reading discipline" per S2-3 §11: combiner MUST read
    ///      pubkey-as-of-block(commit), not pubkey-as-of-now, so that mid-commit
    ///      rotations cannot replay an old commit under a fresh KEM key. Reverse
    ///      iteration finds the most-recent entry with effectiveBlock <= blockNumber.
    ///      Tombstoned entries (tombstoneBlock != 0 and blockNumber >= tombstone)
    ///      revert as Unknown — the consumer treats this as gate-pubkey-retired
    ///      and cannot proceed with reveal.
    function getPubkeyAt(bytes32 authorizationId, uint8 gateKind, uint16 conditionalRecipientIndex, uint64 blockNumber)
        external
        view
        returns (GateRecipientPubkeyEntry memory)
    {
        bytes32 key = _key(authorizationId, gateKind, conditionalRecipientIndex);
        GateRecipientPubkeyEntry[] storage entries = _entriesByKey[key];
        for (uint256 i = entries.length; i > 0; --i) {
            GateRecipientPubkeyEntry storage entry = entries[i - 1];
            if (entry.effectiveBlock <= blockNumber) {
                if (entry.tombstoneBlock != 0 && blockNumber >= entry.tombstoneBlock) {
                    revert GatePubkeyUnknown(authorizationId, gateKind, conditionalRecipientIndex);
                }
                return entry;
            }
        }
        revert GatePubkeyUnknown(authorizationId, gateKind, conditionalRecipientIndex);
    }

    function historyLength(bytes32 authorizationId, uint8 gateKind, uint16 conditionalRecipientIndex)
        external
        view
        returns (uint256)
    {
        return _entriesByKey[_key(authorizationId, gateKind, conditionalRecipientIndex)].length;
    }

    function _key(bytes32 authorizationId, uint8 gateKind, uint16 conditionalRecipientIndex)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(authorizationId, gateKind, conditionalRecipientIndex));
    }

    function _requireNotPaused(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert GatePubkeyPaused(scope);
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
