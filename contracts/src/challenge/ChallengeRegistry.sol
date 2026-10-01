// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { CeremonyAxis, PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";

/// @title ChallengeRegistry - reveal/shred challenge window management
/// @notice Implements the dispute/challenge window that sits between condition-firing
///         and σ-signature collection for both reveal and shred ceremonies. A
///         challenge halts the ceremony for the configured window; resolvers
///         (CHALLENGE_RESOLVER_ROLE per-config, NOT a global role) decide
///         confirmed-no-intervention vs halted vs withdrawn vs dismissed.
/// @dev Two-axis (CeremonyAxis.Reveal vs CeremonyAxis.Shred) — each
///      authorizationId can have ONE open challenge per axis. Storage keyed by
///      (authorizationId, axis) tuple via _key. Bond escrow: challenger posts
///      bond at open time; ChallengeResolved decides distribution. Extension
///      cap (maxExtensions): prevents indefinite-stall DoS. 6 ChallengeReason
///      codes cover the GDPR + integrity + legal-hold cases. Pause scope
///      NEW_CHALLENGE_SCOPE allows pausing new challenges WITHOUT blocking
///      resolution of existing ones — important for emergency-governance.
contract ChallengeRegistry is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable, ReentrancyGuardTransient {
    enum ChallengeStatus {
        None,
        Open,
        ConfirmedNoIntervention,
        Halted,
        Expired,
        Withdrawn,
        Dismissed
    }

    enum ChallengeReason {
        OracleAttestationDisputed,
        ConditionMisapplied,
        LegalHoldAsserted,
        Art22InterventionRequested,
        DataSubjectErasureInvoked,
        IntegrityClaim
    }

    error ChallengeWindowClosed(bytes32 authorizationId, CeremonyAxis axis);
    error ChallengeWindowZero(bytes32 authorizationId, CeremonyAxis axis);
    error ChallengeIneligibleCaller(bytes32 authorizationId, CeremonyAxis axis, address caller);
    error ChallengeProofInvalid(bytes32 authorizationId, CeremonyAxis axis, address caller);
    error ChallengeForfeitNoDestination(bytes32 authorizationId, CeremonyAxis axis);
    error ChallengeAlreadyOpen(bytes32 authorizationId, CeremonyAxis axis);
    error ChallengeBondTooLow(bytes32 authorizationId, uint256 required, uint256 provided);
    error ChallengeCounterAttestationMalformed(bytes32 authorizationId, bytes32 counterAttestationRef);
    error ChallengeResolverUnauthorized(bytes32 authorizationId, address caller);
    error ChallengeExtensionCapReached(bytes32 authorizationId, CeremonyAxis axis);
    error ChallengePaused(bytes32 scope);
    error ChallengeTransferFailed(bytes32 authorizationId, CeremonyAxis axis);

    event ChallengeOpened(
        bytes32 indexed authorizationId,
        CeremonyAxis indexed axis,
        ChallengeReason reason,
        bytes32 counterAttestationRef,
        address challenger,
        uint256 bond
    );
    event ChallengeResolved(
        bytes32 indexed authorizationId, CeremonyAxis indexed axis, ChallengeStatus status, bytes32 resolverActionRef
    );
    /// @dev Emitted when a resolved challenge's bond is distributed: refunded to the
    ///      challenger (ConfirmedNoIntervention) or forfeited to the per-config treasury
    ///      (Halted/Dismissed). `recipient` is the address the bond moved to; `amount`
    ///      is the bond value at resolution time (post-move record.bond is zeroed).
    event ChallengeBondSettled(
        bytes32 indexed authorizationId, CeremonyAxis indexed axis, address recipient, uint256 amount
    );
    event ChallengeExtended(bytes32 indexed authorizationId, CeremonyAxis indexed axis, uint64 newDeadline);
    event ChallengeWithdrawn(bytes32 indexed authorizationId, CeremonyAxis indexed axis, address challenger);
    event ChallengeConfigured(
        bytes32 indexed authorizationId,
        CeremonyAxis indexed axis,
        uint64 windowEnd,
        uint256 requiredBond,
        address eligibleCaller,
        address resolver
    );

    bytes32 public constant UPGRADER_ROLE = Roles.UPGRADER_ROLE;
    bytes32 public constant PAUSER_ROLE = Roles.PAUSER_ROLE;
    bytes32 public constant ORCHESTRATOR_ROLE = Roles.ORCHESTRATOR_ROLE;
    bytes32 public constant CHALLENGE_RESOLVER_ROLE = Roles.CHALLENGE_RESOLVER_ROLE;
    bytes32 public constant NEW_CHALLENGE_SCOPE = keccak256("cealis.challenge.new");

    struct ChallengeConfig {
        uint64 windowEnd;
        uint256 requiredBond;
        bytes32 eligibleChallengersRoot;
        address eligibleCaller;
        address resolver;
        uint8 maxExtensions;
        // Append-only (after maxExtensions) to preserve UUPS storage layout for this
        // mapping-value struct. Destination for a forfeited bond when a challenge is
        // resolved Halted/Dismissed (bad-faith challenge). address(0) = forfeit
        // disabled; a Halted/Dismissed resolution then reverts ChallengeForfeitNo
        // destination so the bond is never silently stranded.
        address forfeitTreasury;
    }

    struct ChallengeRecord {
        ChallengeStatus status;
        ChallengeReason reason;
        bytes32 counterAttestationRef;
        address challenger;
        uint256 bond;
        uint64 deadline;
        uint8 extensionCount;
        bytes32 resolverActionRef;
    }

    mapping(bytes32 => ChallengeConfig) private _configs;
    mapping(bytes32 => ChallengeRecord) private _records;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
    }

    /// @notice Configures a challenge window for an authorization + ceremony axis.
    /// @dev ORCHESTRATOR_ROLE only. Configures BEFORE any challenge can open.
    ///      eligibleCaller is the privileged caller path; eligibleChallengersRoot
    ///      is the merkle root for permissionless-but-allowlisted opening (the
    ///      challenger MUST be in the merkle set, proven at openChallenge time via
    ///      MerkleProof.verifyCalldata over keccak256(abi.encodePacked(msg.sender))).
    ///      resolver is the per-config address that can resolve THIS challenge (not a
    ///      global role — enables per-PDA resolver delegation). maxExtensions caps the
    ///      number of times the window can be extended (DoS-bound). forfeitTreasury is
    ///      the destination for a bond forfeited on a Halted/Dismissed resolution
    ///      (bad-faith challenge); address(0) disables forfeit (a Halted resolution
    ///      then reverts rather than silently stranding the bond). Overwriting a prior
    ///      config is permitted but should be done before the prior window opens.
    function configureChallenge(
        bytes32 authorizationId,
        CeremonyAxis axis,
        uint64 windowEnd,
        uint256 requiredBond,
        bytes32 eligibleChallengersRoot,
        address eligibleCaller,
        address resolver,
        uint8 maxExtensions,
        address forfeitTreasury
    ) external onlyRole(Roles.ORCHESTRATOR_ROLE) {
        _configs[_key(authorizationId, axis)] = ChallengeConfig({
            windowEnd: windowEnd,
            requiredBond: requiredBond,
            eligibleChallengersRoot: eligibleChallengersRoot,
            eligibleCaller: eligibleCaller,
            resolver: resolver,
            maxExtensions: maxExtensions,
            forfeitTreasury: forfeitTreasury
        });
        emit ChallengeConfigured(authorizationId, axis, windowEnd, requiredBond, eligibleCaller, resolver);
    }

    /// @notice Opens a challenge against an authorization's ceremony axis within the window.
    /// @dev Caller gating is two-mode, mirroring ChallengeConfig:
    ///      - eligibleCaller != address(0): privileged single-caller path (msg.sender must match).
    ///      - eligibleChallengersRoot != bytes32(0): permissionless-but-allowlisted path —
    ///        msg.sender MUST prove membership in the merkle set via `merkleProof` over the
    ///        leaf keccak256(abi.encodePacked(msg.sender)). An empty/wrong proof reverts
    ///        ChallengeProofInvalid. The two modes compose (both checks run when both are set).
    ///      When neither is set the open is fully permissionless by configuration intent.
    function openChallenge(
        bytes32 authorizationId,
        CeremonyAxis axis,
        ChallengeReason reason,
        bytes32 counterAttestationRef,
        uint256 bondAmount,
        bytes32[] calldata merkleProof
    ) external payable {
        _requireNotPaused(NEW_CHALLENGE_SCOPE);
        bytes32 key = _key(authorizationId, axis);
        ChallengeConfig memory config = _configs[key];
        if (config.windowEnd == 0) {
            revert ChallengeWindowZero(authorizationId, axis);
        }
        if (block.timestamp > config.windowEnd) {
            revert ChallengeWindowClosed(authorizationId, axis);
        }
        if (config.eligibleCaller != address(0) && msg.sender != config.eligibleCaller) {
            revert ChallengeIneligibleCaller(authorizationId, axis, msg.sender);
        }
        if (config.eligibleChallengersRoot != bytes32(0)) {
            bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
            if (!MerkleProof.verifyCalldata(merkleProof, config.eligibleChallengersRoot, leaf)) {
                revert ChallengeProofInvalid(authorizationId, axis, msg.sender);
            }
        }
        if (_records[key].status == ChallengeStatus.Open) {
            revert ChallengeAlreadyOpen(authorizationId, axis);
        }
        if (msg.value < config.requiredBond || bondAmount < config.requiredBond || msg.value < bondAmount) {
            revert ChallengeBondTooLow(authorizationId, config.requiredBond, msg.value);
        }
        if (counterAttestationRef == bytes32(0)) {
            revert ChallengeCounterAttestationMalformed(authorizationId, counterAttestationRef);
        }

        _records[key] = ChallengeRecord({
            status: ChallengeStatus.Open,
            reason: reason,
            counterAttestationRef: counterAttestationRef,
            challenger: msg.sender,
            bond: msg.value,
            deadline: config.windowEnd,
            extensionCount: 0,
            resolverActionRef: bytes32(0)
        });
        emit ChallengeOpened(authorizationId, axis, reason, counterAttestationRef, msg.sender, msg.value);
    }

    /// @notice Resolver action 1 of 3: closes the challenge window with no intervention.
    /// @dev Caller MUST be the PDA-bound resolver per S2-6 §12.7. Lifecycle proceeds
    ///      to ceremony fire after this. Pairs with haltCeremony (action 2) and
    ///      extendChallenge (action 3). Halt-only resolution model — no `withdraw`
    ///      resolver action exists; withdrawal is challenger-initiated.
    function confirmNoIntervention(bytes32 authorizationId, CeremonyAxis axis, bytes32 resolverActionRef)
        external
        nonReentrant
    {
        _resolve(authorizationId, axis, resolverActionRef, ChallengeStatus.ConfirmedNoIntervention);
    }

    /// @notice Resolver action 2 of 3: halts the ceremony, preventing further progress.
    /// @dev Caller MUST be the PDA-bound resolver. Halt is terminal for the ceremony;
    ///      no resume path exists by design (S2-6 §12.7 halt-only model).
    function haltCeremony(bytes32 authorizationId, CeremonyAxis axis, bytes32 resolverActionRef)
        external
        nonReentrant
    {
        _resolve(authorizationId, axis, resolverActionRef, ChallengeStatus.Halted);
    }

    /// @notice Resolver action 3 of 3: extends the challenge window deadline.
    /// @dev Caller MUST be the resolver. Bounded by ChallengeConfig.maxExtensions
    ///      (`CHALLENGE_EXTENSION_MAX_DAYS` in spec). newDeadline must strictly
    ///      exceed current deadline. Increments extensionCount.
    function extendChallenge(bytes32 authorizationId, CeremonyAxis axis, uint64 newDeadline) external {
        bytes32 key = _key(authorizationId, axis);
        ChallengeConfig memory config = _configs[key];
        _requireResolver(authorizationId, msg.sender, config);
        ChallengeRecord storage record = _records[key];
        if (record.status != ChallengeStatus.Open) {
            revert ChallengeWindowClosed(authorizationId, axis);
        }
        if (record.extensionCount >= config.maxExtensions) {
            revert ChallengeExtensionCapReached(authorizationId, axis);
        }
        if (newDeadline <= record.deadline) {
            revert ChallengeWindowClosed(authorizationId, axis);
        }
        record.deadline = newDeadline;
        record.extensionCount += 1;
        emit ChallengeExtended(authorizationId, axis, newDeadline);
    }

    /// @notice Challenger withdraws their open challenge, recovering the posted bond.
    /// @dev Caller MUST be the challenger (per record.challenger). Distinct from the
    ///      3 resolver actions — this is challenger-initiated. Bond refund happens
    ///      via low-level call; revert on failure. Lifecycle proceeds as if no
    ///      challenge was raised.
    function withdrawChallenge(bytes32 authorizationId, CeremonyAxis axis) external nonReentrant {
        bytes32 key = _key(authorizationId, axis);
        ChallengeRecord storage record = _records[key];
        if (record.status != ChallengeStatus.Open) {
            revert ChallengeWindowClosed(authorizationId, axis);
        }
        if (msg.sender != record.challenger) {
            revert ChallengeIneligibleCaller(authorizationId, axis, msg.sender);
        }
        uint256 bond = record.bond;
        record.status = ChallengeStatus.Withdrawn;
        record.bond = 0;
        emit ChallengeWithdrawn(authorizationId, axis, msg.sender);
        (bool ok,) = msg.sender.call{ value: bond }("");
        if (!ok) {
            revert ChallengeTransferFailed(authorizationId, axis);
        }
    }

    function challengeStatus(bytes32 authorizationId, CeremonyAxis axis) external view returns (ChallengeStatus) {
        ChallengeRecord memory record = _records[_key(authorizationId, axis)];
        if (record.status == ChallengeStatus.Open && block.timestamp > record.deadline) {
            return ChallengeStatus.Expired;
        }
        return record.status;
    }

    function challengeConfig(bytes32 authorizationId, CeremonyAxis axis)
        external
        view
        returns (ChallengeConfig memory)
    {
        return _configs[_key(authorizationId, axis)];
    }

    /// @dev Resolves an open challenge and settles the posted bond per the outcome,
    ///      following checks-effects-interactions:
    ///      - ConfirmedNoIntervention (honest challenge upheld): refund bond to challenger.
    ///      - Halted/Dismissed (challenge defeated / bad-faith): forfeit bond to the
    ///        per-config forfeitTreasury. A non-zero bond with an unset treasury reverts
    ///        ChallengeForfeitNoDestination so the bond is never silently stranded.
    ///      record.bond is zeroed BEFORE the external transfer; the only external call is
    ///      the value transfer at the end. Callers (confirmNoIntervention/haltCeremony)
    ///      carry nonReentrant.
    function _resolve(bytes32 authorizationId, CeremonyAxis axis, bytes32 resolverActionRef, ChallengeStatus status)
        internal
    {
        bytes32 key = _key(authorizationId, axis);
        ChallengeConfig memory config = _configs[key];
        _requireResolver(authorizationId, msg.sender, config);
        ChallengeRecord storage record = _records[key];
        if (record.status != ChallengeStatus.Open) {
            revert ChallengeWindowClosed(authorizationId, axis);
        }

        uint256 bond = record.bond;
        address recipient;
        if (status == ChallengeStatus.ConfirmedNoIntervention) {
            recipient = record.challenger;
        } else {
            // Halted / Dismissed: forfeit the bond. Refuse to silently strand it.
            recipient = config.forfeitTreasury;
            if (bond != 0 && recipient == address(0)) {
                revert ChallengeForfeitNoDestination(authorizationId, axis);
            }
        }

        // Effects (CEI): finalize status and zero the bond before any transfer.
        record.status = status;
        record.resolverActionRef = resolverActionRef;
        record.bond = 0;
        emit ChallengeResolved(authorizationId, axis, status, resolverActionRef);

        // Interaction: settle the bond last.
        if (bond != 0) {
            emit ChallengeBondSettled(authorizationId, axis, recipient, bond);
            (bool ok,) = recipient.call{ value: bond }("");
            if (!ok) {
                revert ChallengeTransferFailed(authorizationId, axis);
            }
        }
    }

    function _requireResolver(bytes32 authorizationId, address caller, ChallengeConfig memory config) internal view {
        if (caller != config.resolver || !hasRole(Roles.CHALLENGE_RESOLVER_ROLE, caller)) {
            revert ChallengeResolverUnauthorized(authorizationId, caller);
        }
    }

    function _key(bytes32 authorizationId, CeremonyAxis axis) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(authorizationId, uint8(axis)));
    }

    function _requireNotPaused(bytes32 scope) internal view {
        if (_pauses[scope].until != 0 && block.timestamp < _pauses[scope].until) {
            revert ChallengePaused(scope);
        }
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (!hasRole(Roles.PAUSER_ROLE, caller)) {
            revert PauseUnauthorized(scope, caller);
        }
    }

    function _maxPauseDuration() internal pure override returns (uint64) {
        return PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
    }

    function _pauseAuthorityMode(bytes32) internal pure override returns (PauseAuthorityMode) {
        return PauseAuthorityMode.Joint;
    }

    function _authorizeUpgrade(address) internal override onlyRole(Roles.UPGRADER_ROLE) { }

    uint256[50] private __gap;
}
