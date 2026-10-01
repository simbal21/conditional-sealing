// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { CealisIdentifierHelpers } from "../../src/helpers/CealisIdentifierHelpers.sol";
import { IConditionEngine, IFSMInterpreter } from "../../src/engine/IConditionEngine.sol";
import {
    CeremonyAxis,
    ConditionMode,
    ConditionalRecipientMode,
    G4Phase,
    LifecycleState
} from "../../src/lib/Enums.sol";
import { PDARegistration, FSMAdvanceResult } from "../../src/lib/Structs.sol";

contract MockConditionEngine is IConditionEngine {
    struct Record {
        PDARegistration registration;
        bytes32 hCommit;
        bytes32 pdaRoot;
        bool registered;
        bool postChallengeReveal;
        LifecycleState state;
    }

    CealisIdentifierHelpers private immutable _helpers = new CealisIdentifierHelpers();
    IFSMInterpreter private _fsmInterpreter;
    mapping(bytes32 => Record) private _records;

    function setFSMInterpreter(address fsmInterpreter) external {
        _fsmInterpreter = IFSMInterpreter(fsmInterpreter);
    }

    function registerPDA(PDARegistration calldata registration) external {
        bytes32 authorizationId = registration.hCommitFields.authorizationId;
        if (_records[authorizationId].registered) revert ConditionAlreadyRegistered(authorizationId);
        if (registration.revealAxis.mode == ConditionMode.None || registration.shredAxis.mode == ConditionMode.None) {
            revert ConditionInvalidMode(uint8(registration.revealAxis.mode));
        }
        for (uint256 i = 0; i < registration.conditionalRecipientModes.length; ++i) {
            if (registration.conditionalRecipientModes[i] == ConditionalRecipientMode.WalletEIP1271Reserved) {
                revert ConditionMode3Reserved(authorizationId);
            }
        }
        if (registration.legalFlags.legalEffectExpected && registration.legalFlags.requiredG4Phase == G4Phase.Phase1) {
            revert ConditionLegalEffectPhaseInvalid(authorizationId, uint8(G4Phase.Phase1));
        }
        if (registration.legalFlags.legalEffectExpected && registration.legalFlags.cealisClassWideHaltOptOut) {
            revert ConditionLegalEffectHaltOptOutForbidden(authorizationId);
        }
        if (!registration.shredGuardrailCompiled) revert ConditionShredGuardrailMissing(authorizationId);

        bytes32 pdaRoot = _helpers.computePdaRoot(registration.pdaRootFields);
        if (pdaRoot != registration.hCommitFields.pdaRoot) {
            revert ConditionHCommitPdaRootMismatch(registration.hCommitFields.pdaRoot, pdaRoot);
        }
        bytes32 hCommit = _helpers.computeHCommit(registration.hCommitFields);
        _records[authorizationId].registration = registration;
        _records[authorizationId].hCommit = hCommit;
        _records[authorizationId].pdaRoot = pdaRoot;
        _records[authorizationId].registered = true;
        _records[authorizationId].state = LifecycleState.Registered;
        emit PDARegistered(authorizationId, hCommit, pdaRoot, registration.pdaRootFields.partnerId);
        emit LifecycleStateChanged(authorizationId, LifecycleState.Unregistered, LifecycleState.Registered);
    }

    function authorizeReveal(bytes32 authorizationId, bytes32 evidenceRef) external {
        Record storage record = _requireRecord(authorizationId);
        LifecycleState oldState = record.state;
        record.state = LifecycleState.PostChallengeRevealInProgress;
        record.postChallengeReveal = true;
        emit RevealAuthorized(
            authorizationId,
            record.hCommit,
            record.pdaRoot,
            uint64(block.number),
            uint64(block.timestamp),
            record.registration.revealAxis.challengeWindow,
            evidenceRef
        );
        emit LifecycleStateChanged(authorizationId, oldState, record.state);
    }

    function authorizeShred(bytes32 authorizationId, bytes32 evidenceRef) external {
        Record storage record = _requireRecord(authorizationId);
        LifecycleState oldState = record.state;
        record.state = LifecycleState.ShredConditionMet;
        emit ShredAuthorized(
            authorizationId,
            record.hCommit,
            record.pdaRoot,
            uint64(block.number),
            uint64(block.timestamp),
            record.registration.shredAxis.challengeWindow,
            evidenceRef
        );
        emit LifecycleStateChanged(authorizationId, oldState, record.state);
    }

    function advanceFSM(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 transitionId,
        bytes32 attestationDigest,
        bytes calldata transitionProof
    ) external returns (FSMAdvanceResult memory result) {
        if (address(_fsmInterpreter) == address(0)) {
            revert ConditionUnknownAuthorization(authorizationId);
        }
        return _fsmInterpreter.advanceFSM(
            authorizationId, axis, msg.sender, transitionId, attestationDigest, transitionProof
        );
    }

    function canGatesSign(bytes32 authorizationId) external view returns (bool) {
        return _records[authorizationId].postChallengeReveal;
    }

    function postChallengeRevealInProgress(bytes32 authorizationId) external view returns (bool) {
        return _records[authorizationId].postChallengeReveal;
    }

    function lifecycleState(bytes32 authorizationId) external view returns (LifecycleState) {
        return _records[authorizationId].state;
    }

    function pdaRegistration(bytes32 authorizationId) external view returns (PDARegistration memory) {
        return _records[authorizationId].registration;
    }

    function _requireRecord(bytes32 authorizationId) private view returns (Record storage record) {
        record = _records[authorizationId];
        if (!record.registered) revert ConditionUnknownAuthorization(authorizationId);
    }
}
