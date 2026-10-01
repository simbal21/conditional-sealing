// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IAttestationGate, IOracleAttestationModule } from "../engine/IConditionEngine.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import { ConditionModuleBase } from "./PaymentObligationModule.sol";

/// @title OracleAttestationModule - condition module for oracle-attested reveal triggers
/// @notice One of the 9 ConditionEngine modules. Fires when an authorized oracle (per
///         OracleRegistry) submits an attestation matching the configured (oracleId,
///         schemaId, claimRef) tuple. Drives use cases like price-trigger reveals,
///         court-order attestations, regulator-bound disclosures, QTSP-signed events.
/// @dev Reentrancy: state-after-external-call pattern (verifyOracleAttestation is
///      external) is hardened via OZ ReentrancyGuardTransient + nonReentrant on the
///      external entry point. Transient storage (EIP-1153) means zero UUPS layout
///      risk. Replay protection: _consumedAttestations mapping prevents reuse of
///      attestationDigest across any (authorizationId) — global once-and-only-once.
///      Freshness: when freshnessWindow != 0 + already consumed, further submissions
///      revert OracleAttestationFreshnessExpired (one-shot oracle binding).
contract OracleAttestationModule is ConditionModuleBase, ReentrancyGuardTransient, IOracleAttestationModule {
    struct OracleConditionState {
        bytes32 oracleId;
        bytes32 schemaId;
        bytes32 claimRef;
        bytes32 acceptedAttestationDigest;
        uint64 freshnessWindow;
        bool consumed;
    }

    IAttestationGate private _attestationGate;
    mapping(bytes32 => OracleConditionState) private _oracleConditions;
    mapping(bytes32 => bool) private _consumedAttestations;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine, address attestationGate_) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
        _attestationGate = IAttestationGate(attestationGate_);
    }

    /// @notice Configures the oracle condition for a given authorizationId.
    /// @dev Access: onlyConditionEngineOrModuleAdmin (ConditionEngine on commit, or
    ///      MODULE_ADMIN_ROLE for governance-correction). Overwrites any prior
    ///      config. configDigest binds the off-chain config payload for §371a ZPO
    ///      audit trail. claimRef is the DSL-encoded predicate (e.g., "price >= X"
    ///      or "consent_for_subject(authorizationId)") evaluated by the
    ///      AttestationGate at submit-time. freshnessWindow=0 means no freshness
    ///      check (one-shot binding); !=0 means subsequent submissions revert
    ///      after consumption.
    function configureOracleCondition(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 claimRef,
        uint64 freshnessWindow,
        bytes32 configDigest
    ) external onlyConditionEngineOrModuleAdmin {
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: oracleId, configDigest: configDigest });
        _oracleConditions[authorizationId] = OracleConditionState({
            oracleId: oracleId,
            schemaId: schemaId,
            claimRef: claimRef,
            acceptedAttestationDigest: bytes32(0),
            freshnessWindow: freshnessWindow,
            consumed: false
        });
        emit ModuleConfigured(authorizationId, oracleId, configDigest);
    }

    /// @notice Submits an oracle-signed attestation that may fire this condition.
    /// @dev Access: onlyConditionEngine (entry MUST come through ConditionEngine,
    ///      never directly). nonReentrant: OZ transient-storage guard prevents
    ///      reentry through the IAttestationGate.verifyOracleAttestation external
    ///      call. Slither reports state-after-external-call but the guard +
    ///      access control + replay set make this safe. `proof` is reserved for
    ///      ZK-attestation extensions and currently unused on this path; the
    ///      internal _advanceModule helper carries the proof-encoded variant.
    function submitOracleAttestation(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes calldata oracleSignature,
        bytes calldata proof
    ) external onlyConditionEngine nonReentrant {
        proof;
        _submitOracleAttestation(authorizationId, oracleId, schemaId, attestationDigest, oracleSignature);
    }

    function oracleConditionState(bytes32 authorizationId) external view returns (OracleConditionState memory) {
        _requireKnown(authorizationId);
        return _oracleConditions[authorizationId];
    }

    function attestationGate() external view returns (address) {
        return address(_attestationGate);
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32)
        internal
        override
    {
        (bytes32 schemaId, bytes32 claimRef, uint64 freshnessWindow) = abi.decode(config, (bytes32, bytes32, uint64));
        _oracleConditions[authorizationId] = OracleConditionState({
            oracleId: moduleRef,
            schemaId: schemaId,
            claimRef: claimRef,
            acceptedAttestationDigest: bytes32(0),
            freshnessWindow: freshnessWindow,
            consumed: false
        });
    }

    function _advanceModule(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        internal
        override
        returns (bool)
    {
        if (proof.length != 0) {
            (bytes32 oracleId, bytes32 schemaId, bytes memory signature) = abi.decode(proof, (bytes32, bytes32, bytes));
            _submitOracleAttestation(authorizationId, oracleId, schemaId, evidenceRef, signature);
        }
        return _oracleConditions[authorizationId].acceptedAttestationDigest == evidenceRef;
    }

    function _evaluateModule(bytes32 authorizationId, bytes32 contextRef) internal view override returns (bool) {
        OracleConditionState memory state = _oracleConditions[authorizationId];
        return state.consumed && (contextRef == bytes32(0) || contextRef == state.acceptedAttestationDigest);
    }

    function _submitOracleAttestation(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes memory oracleSignature
    ) private {
        _requireKnown(authorizationId);
        _requireNotPaused(authorizationId);
        OracleConditionState storage state = _oracleConditions[authorizationId];
        if (state.oracleId != oracleId) revert OracleAttestationRootMismatch(authorizationId, oracleId);
        if (_consumedAttestations[attestationDigest]) revert OracleAttestationDigestConsumed(attestationDigest);
        if (state.freshnessWindow != 0 && state.consumed) {
            revert OracleAttestationFreshnessExpired(attestationDigest);
        }
        // slither-disable-next-line reentrancy-no-eth -- replay guard checked at line above (_consumedAttestations / state.consumed) before the call; _attestationGate is a Cealis-governed contract whose own external calls (ClaimDSL, ecrecover, Cealis registries) do not re-enter this module, so the post-call state writes are not reentrancy-reachable by an attacker. AUDITOR NOTE: defense-in-depth nonReentrant on the external entrypoint is a candidate hardening (cf. SC-F-03/F-07).
        bool ok = _attestationGate.verifyOracleAttestation(
            authorizationId, oracleId, schemaId, attestationDigest, oracleSignature, state.claimRef
        );
        if (!ok) revert ModuleConditionFalse(authorizationId);
        state.acceptedAttestationDigest = attestationDigest;
        state.schemaId = schemaId;
        state.consumed = true;
        _consumedAttestations[attestationDigest] = true;
        emit OracleConditionAccepted(authorizationId, oracleId, attestationDigest);
    }

    uint256[50] private __gap;
}
