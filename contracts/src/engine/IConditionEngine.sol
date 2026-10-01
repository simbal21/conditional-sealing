// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { CeremonyAxis, LifecycleState } from "../lib/Enums.sol";
import { PDARegistration, FSMAdvanceResult } from "../lib/Structs.sol";

/// @notice Interface-only D1 surface. Phase D2 owns the concrete ConditionEngine body.
interface IConditionEngine {
    error ConditionUnknownAuthorization(bytes32 authorizationId);
    error ConditionAlreadyRegistered(bytes32 authorizationId);
    error ConditionInvalidMode(uint8 mode);
    error ConditionPaused(bytes32 authorizationId);
    error ConditionShredded(bytes32 hCommit);
    error ConditionNotMet(bytes32 authorizationId, CeremonyAxis axis);
    error ConditionChallengeWindowActive(bytes32 authorizationId, CeremonyAxis axis);
    error ConditionMode3Reserved(bytes32 authorizationId);
    error ConditionLegalEffectPhaseInvalid(bytes32 authorizationId, uint8 phase);
    error ConditionLegalEffectHaltOptOutForbidden(bytes32 authorizationId);
    error ConditionShredGuardrailMissing(bytes32 authorizationId);
    error ConditionPdaRootMismatch(bytes32 computed, bytes32 supplied);
    error ConditionHCommitPdaRootMismatch(bytes32 hCommitPdaRoot, bytes32 computedPdaRoot);
    error ConditionPauseAuthorityInvalid(uint8 mode);

    event PDARegistered(
        bytes32 indexed authorizationId, bytes32 indexed hCommit, bytes32 indexed pdaRoot, bytes32 partnerId
    );
    event RevealAuthorized(
        bytes32 indexed authorizationId,
        bytes32 indexed hCommit,
        bytes32 indexed pdaRoot,
        uint64 authorizationBlock,
        uint64 authorizationTimestamp,
        uint32 challengeWindow,
        bytes32 conditionRef
    );
    event ShredAuthorized(
        bytes32 indexed authorizationId,
        bytes32 indexed hCommit,
        bytes32 indexed pdaRoot,
        uint64 authorizationBlock,
        uint64 authorizationTimestamp,
        uint32 challengeWindow,
        bytes32 conditionRef
    );
    event LifecycleStateChanged(bytes32 indexed authorizationId, LifecycleState oldState, LifecycleState newState);

    function registerPDA(PDARegistration calldata registration) external;
    function authorizeReveal(bytes32 authorizationId, bytes32 evidenceRef) external;
    function authorizeShred(bytes32 authorizationId, bytes32 evidenceRef) external;
    function advanceFSM(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 transitionId,
        bytes32 attestationDigest,
        bytes calldata transitionProof
    ) external returns (FSMAdvanceResult memory result);
    function canGatesSign(bytes32 authorizationId) external view returns (bool);
    function postChallengeRevealInProgress(bytes32 authorizationId) external view returns (bool);
    function lifecycleState(bytes32 authorizationId) external view returns (LifecycleState);
}

interface IConditionModule {
    error ModuleUnauthorizedCaller(address caller);
    error ModuleUnknownAuthorization(bytes32 authorizationId);
    error ModuleConditionFalse(bytes32 authorizationId);
    error ModuleInvalidEvidence(bytes32 evidenceRef);
    error ModuleGasBudgetExceeded(bytes32 authorizationId);

    event ModuleConfigured(bytes32 indexed authorizationId, bytes32 indexed moduleRef, bytes32 configDigest);
    event ModuleAdvanced(bytes32 indexed authorizationId, bytes32 indexed evidenceRef, bool terminal);

    function configure(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config) external;
    function advance(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof)
        external
        returns (bool terminal);
    function evaluate(bytes32 authorizationId, bytes32 contextRef) external view returns (bool);
}

interface IFSMInterpreter {
    error FSMUnknown(bytes32 authorizationId, CeremonyAxis axis);
    error FSMInvalidTransition(bytes32 authorizationId, uint32 fromState, bytes32 transitionId);
    error FSMUnauthorizedSubmitter(bytes32 authorizationId, address submitter);
    error FSMUnauthorizedCaller(address caller);
    error FSMHashMismatch(bytes32 authorizationId, bytes32 expected, bytes32 actual);
    error FSMGasBudgetExceeded(bytes32 authorizationId);

    event FSMAdvanced(
        bytes32 indexed authorizationId,
        CeremonyAxis indexed axis,
        uint32 fromState,
        uint32 toState,
        bytes32 transitionId,
        bool terminal
    );

    function advanceFSM(
        bytes32 authorizationId,
        CeremonyAxis axis,
        address actor,
        bytes32 transitionId,
        bytes32 attestationDigest,
        bytes calldata transitionProof
    ) external returns (FSMAdvanceResult memory result);

    function currentState(bytes32 authorizationId, CeremonyAxis axis) external view returns (uint32);
}

interface IClaimDSL {
    error DSLUnsupportedVersion(bytes32 dslVersionRef);
    error DSLInvalidOperator(uint8 op);
    error DSLTypeMismatch(uint16 nodeIndex);
    error DSLGasBudgetExceeded(bytes32 claimRef);
    error DSLCustomPredicateReserved(bytes32 wasmHash);

    event DSLVersionUsed(bytes32 indexed dslVersionRef, bytes32 indexed claimRef);

    function evaluateClaim(bytes32 dslVersionRef, bytes32 claimRef, bytes32 contextRef) external view returns (bool);
}

interface IAttestationGate {
    error AttestationOracleUnknown(bytes32 oracleId);
    error AttestationSchemaMismatch(bytes32 oracleId, bytes32 schemaId);
    error AttestationSignatureInvalid(bytes32 oracleId, bytes32 attestationDigest);
    error AttestationStale(bytes32 attestationDigest);
    error AttestationClaimFalse(bytes32 claimRef);
    error AttestationSigmaBytesForbidden();

    event OracleAttestationAccepted(
        bytes32 indexed authorizationId,
        bytes32 indexed oracleId,
        bytes32 indexed attestationDigest,
        bytes32 schemaId,
        bytes32 claimRef
    );

    function verifyOracleAttestation(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes calldata oracleSignature,
        bytes32 claimRef
    ) external returns (bool);
}

interface IPaymentObligationModule is IConditionModule {
    error PaymentObligationInactive(bytes32 obligationRef);
    error PaymentObligationAlreadyDefaulted(bytes32 obligationRef);
    error PaymentObligationCureWindowActive(bytes32 obligationRef);
    error PaymentObligationEvidenceMismatch(bytes32 obligationRef, bytes32 evidenceRef);

    event PaymentObserved(bytes32 indexed authorizationId, bytes32 indexed obligationRef, bytes32 paymentDigest);
    event DefaultObserved(bytes32 indexed authorizationId, bytes32 indexed obligationRef, bytes32 defaultDigest);
    event CureObserved(bytes32 indexed authorizationId, bytes32 indexed obligationRef, bytes32 cureDigest);

    function registerObligation(bytes32 authorizationId, bytes32 obligationRef, bytes32 configDigest) external;
    function markPaymentObserved(bytes32 obligationRef, bytes32 paymentDigest) external;
    function markDefaultObserved(bytes32 obligationRef, bytes32 defaultDigest) external;
    function obligationStatus(bytes32 obligationRef)
        external
        view
        returns (uint8 status, uint64 dueAt, uint64 cureDeadline);
}

interface ITimeLockModule is IConditionModule {
    error TimeLockTargetInvalid(bytes32 authorizationId);
    error TimeLockNotReached(bytes32 authorizationId, uint64 target, uint64 currentTime);
    error TimeLockWindowExpired(bytes32 authorizationId);

    event TimeLockConfigured(bytes32 indexed authorizationId, uint64 targetTimestamp, uint8 clockSource);
    event TimeLockReached(bytes32 indexed authorizationId, uint64 reachedAt);

    function configureTimeLock(bytes32 authorizationId, bytes32 configDigest, uint64 targetTimestamp, uint8 clockSource)
        external;
    function evaluateTimeLock(bytes32 authorizationId) external view returns (bool);
}

interface ISubjectInitiatedModule is IConditionModule {
    error SubjectInitiatedNonceConsumed(bytes32 authorizationId, uint256 nonce);
    error SubjectInitiatedExpired(bytes32 authorizationId, uint64 expiresAt);
    error SubjectInitiatedInvalidSigner(bytes32 authorizationId);
    error SubjectInitiatedAxisMismatch(bytes32 authorizationId, CeremonyAxis expected, CeremonyAxis actual);

    event SubjectActionAccepted(
        bytes32 indexed authorizationId, CeremonyAxis indexed axis, bytes32 actionDigest, uint256 nonce
    );

    function submitSubjectInitiated(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 actionDigest,
        bytes calldata signatureEnvelopeRef,
        uint256 nonce,
        uint64 expiresAt
    ) external;
}

interface IHeartbeatMissedModule is IConditionModule {
    error HeartbeatTooEarly(bytes32 authorizationId, uint64 nextAllowedAt);
    error HeartbeatNotMissed(bytes32 authorizationId, uint64 deadline);
    error HeartbeatInvalidActor(bytes32 authorizationId, address caller);

    event HeartbeatRecorded(bytes32 indexed authorizationId, bytes32 indexed actorRef, uint64 nextDeadline);
    event HeartbeatMissed(bytes32 indexed authorizationId, bytes32 indexed actorRef, uint64 missedAt);

    function recordHeartbeat(bytes32 authorizationId, bytes32 heartbeatDigest, bytes calldata signatureEnvelopeRef)
        external;
    function heartbeatDeadline(bytes32 authorizationId) external view returns (uint64);
}

interface IOracleAttestationModule is IConditionModule {
    error OracleAttestationDigestConsumed(bytes32 attestationDigest);
    error OracleAttestationRootMismatch(bytes32 authorizationId, bytes32 oracleId);
    error OracleAttestationFreshnessExpired(bytes32 attestationDigest);

    event OracleConditionAccepted(
        bytes32 indexed authorizationId, bytes32 indexed oracleId, bytes32 indexed attestationDigest
    );

    function submitOracleAttestation(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes calldata oracleSignature,
        bytes calldata proof
    ) external;
}

interface IMultiPartySignalModule is IConditionModule {
    error MultiPartySignalSignerIneligible(bytes32 authorizationId, address signer);
    error MultiPartySignalDuplicateSigner(bytes32 authorizationId, address signer);
    error MultiPartySignalThresholdNotMet(bytes32 authorizationId, uint16 count, uint16 threshold);
    error MultiPartySignalDigestMismatch(bytes32 authorizationId, bytes32 expected, bytes32 actual);

    event SignalSubmitted(bytes32 indexed authorizationId, bytes32 indexed signalDigest, address indexed signer);
    event MultiPartySignalThresholdMet(
        bytes32 indexed authorizationId, bytes32 indexed signalDigest, uint16 count, uint16 threshold
    );

    function submitSignal(
        bytes32 authorizationId,
        address signer,
        bytes32 signalDigest,
        bytes calldata signatureEnvelopeRef,
        bytes calldata proof
    ) external;
    function signalCount(bytes32 authorizationId, bytes32 signalDigest)
        external
        view
        returns (uint16 count, uint16 threshold);
}

interface IDeadManSwitchModule is IConditionModule {
    error DeadManSwitchGraceActive(bytes32 authorizationId, uint64 deadline);
    error DeadManSwitchRecipientPolicyMismatch(bytes32 authorizationId);

    event DeadManSwitchTriggered(bytes32 indexed authorizationId, bytes32 missedHeartbeatRef);

    function recordDeadManHeartbeat(
        bytes32 authorizationId,
        bytes32 heartbeatDigest,
        bytes calldata signatureEnvelopeRef
    ) external;
    function deadManDeadline(bytes32 authorizationId) external view returns (uint64);
}

interface IConsentGateModule is IConditionModule {
    error ConsentAuthorityIneligible(bytes32 authorizationId, address authority);
    error ConsentDigestMismatch(bytes32 authorizationId, bytes32 expected, bytes32 actual);
    error ConsentExpired(bytes32 authorizationId, uint64 expiresAt);

    event ConsentAccepted(bytes32 indexed authorizationId, bytes32 indexed authorityRef, bytes32 consentDigest);

    function submitConsent(
        bytes32 authorizationId,
        address authority,
        bytes32 consentDigest,
        bytes calldata signatureEnvelopeRef,
        bytes calldata proof
    ) external;
}

interface IComposedModule is IConditionModule {
    error ComposedChildCountInvalid(bytes32 authorizationId, uint16 childCount);
    error ComposedDepthExceeded(bytes32 authorizationId, uint16 depth);
    error ComposedChildFalse(bytes32 authorizationId, bytes32 childRef);

    event ComposedConditionMet(bytes32 indexed authorizationId, bytes32 indexed compositionRoot);

    function evaluateComposed(bytes32 authorizationId) external view returns (bool);
}
