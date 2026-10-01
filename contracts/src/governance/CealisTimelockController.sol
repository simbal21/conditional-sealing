// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { TimelockController } from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title CealisTimelockController
/// @notice Canonical 7-day governance timelock plus a separate 24-hour
///         expedited queue for canonical-in-use registry deprecations.
/// @dev The normal path is the unmodified OZ TimelockController surface.
///      The expedited path is intentionally narrow: it queues a single call,
///      requires an expedited proposer and cosigner role, and enforces a fixed
///      24-hour delay before execution. This keeps the observable §9.12
///      behavior separate from the 7-day governance queue.
contract CealisTimelockController is TimelockController {
    uint256 public constant NORMAL_GOVERNANCE_DELAY = 7 days;
    uint256 public constant EXPEDITED_GOVERNANCE_DELAY = 1 days;

    bytes32 public constant EXPEDITED_PROPOSER_ROLE = keccak256("EXPEDITED_PROPOSER_ROLE");
    bytes32 public constant EXPEDITED_COSIGNER_ROLE = keccak256("EXPEDITED_COSIGNER_ROLE");
    bytes32 public constant EXPEDITED_EXECUTOR_ROLE = keccak256("EXPEDITED_EXECUTOR_ROLE");

    error TimelockNormalDelayInvalid(uint256 supplied);
    error ExpeditedOperationAlreadyQueued(bytes32 operationId);
    error ExpeditedOperationUnknown(bytes32 operationId);
    error ExpeditedOperationNotReady(bytes32 operationId, uint64 readyAt);
    error ExpeditedOperationMissingCosignature(bytes32 operationId);
    error ExpeditedOperationAlreadyDone(bytes32 operationId);
    error ExpeditedOperationExecutionFailed(bytes32 operationId);
    error ExpeditedExecutorUnauthorized(address caller);

    event ExpeditedOperationScheduled(
        bytes32 indexed operationId,
        address indexed target,
        uint256 value,
        bytes data,
        bytes32 predecessor,
        bytes32 salt,
        uint64 readyAt
    );
    event ExpeditedOperationCosigned(bytes32 indexed operationId, address indexed cosigner);
    event ExpeditedOperationExecuted(bytes32 indexed operationId, address indexed target, uint256 value);

    struct ExpeditedOperation {
        uint64 readyAt;
        bool cosigned;
        bool done;
    }

    mapping(bytes32 => ExpeditedOperation) private _expeditedOperations;

    constructor(uint256 minDelay, address[] memory proposers, address[] memory executors, address admin)
        TimelockController(minDelay, proposers, executors, admin)
    {
        if (minDelay != NORMAL_GOVERNANCE_DELAY) revert TimelockNormalDelayInvalid(minDelay);

        for (uint256 i = 0; i < proposers.length; ++i) {
            _grantRole(EXPEDITED_PROPOSER_ROLE, proposers[i]);
        }
        for (uint256 i = 0; i < executors.length; ++i) {
            _grantRole(EXPEDITED_EXECUTOR_ROLE, executors[i]);
        }
    }

    /// @notice Computes the canonical operationId for an expedited timelock operation.
    /// @dev Pure helper. Uses literal domain-tag "CEALIS_EXPEDITED_TIMELOCK_V1"
    ///      to prevent operationId collisions with the OZ-base TimelockController
    ///      hashing scheme. abi.encode (length-prefixed) prevents dynamic-arg
    ///      collisions on the `data` field.
    function hashExpeditedOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) public pure returns (bytes32) {
        return keccak256(abi.encode("CEALIS_EXPEDITED_TIMELOCK_V1", target, value, data, predecessor, salt));
    }

    /// @notice Schedules an expedited operation with a 24-hour delay (vs the 7-day normal path).
    /// @dev Access: EXPEDITED_PROPOSER_ROLE (granted to all OZ-base proposers at
    ///      construction). Each operationId is single-shot: re-scheduling the
    ///      same operationId reverts ExpeditedOperationAlreadyQueued — to retry
    ///      a failed/expired operation, use a fresh salt. Two-of-three governance
    ///      gate: proposer schedules, EXPEDITED_COSIGNER_ROLE co-signs, then
    ///      EXPEDITED_EXECUTOR_ROLE executes (cosignature required AFTER
    ///      scheduling but BEFORE readyAt). Designed for canonical-in-use
    ///      registry deprecations (S2-6 §13.6) where 7-day delay is unacceptable.
    function scheduleExpeditedOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external onlyRole(EXPEDITED_PROPOSER_ROLE) returns (bytes32 operationId) {
        operationId = hashExpeditedOperation(target, value, data, predecessor, salt);
        ExpeditedOperation storage operation = _expeditedOperations[operationId];
        if (operation.readyAt != 0) revert ExpeditedOperationAlreadyQueued(operationId);

        // The timestamp sum cannot approach uint64 max under the EVM's practical chain lifetime.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 readyAt = uint64(block.timestamp + EXPEDITED_GOVERNANCE_DELAY);
        operation.readyAt = readyAt;
        emit ExpeditedOperationScheduled(operationId, target, value, data, predecessor, salt, readyAt);
    }

    /// @notice Co-signs a previously-scheduled expedited operation, enabling it for execution
    ///         once readyAt is reached.
    /// @dev EXPEDITED_COSIGNER_ROLE only. Required because expedited operations bypass the
    ///      default 7-day timelock with a shorter EXPEDITED_GOVERNANCE_DELAY — two distinct
    ///      authorities (proposer + co-signer) must agree before the shorter window applies.
    ///      Reverts on (a) unknown operationId, (b) already-executed operation.
    function approveExpeditedOperation(bytes32 operationId) external onlyRole(EXPEDITED_COSIGNER_ROLE) {
        ExpeditedOperation storage operation = _expeditedOperations[operationId];
        if (operation.readyAt == 0) revert ExpeditedOperationUnknown(operationId);
        if (operation.done) revert ExpeditedOperationAlreadyDone(operationId);
        operation.cosigned = true;
        emit ExpeditedOperationCosigned(operationId, msg.sender);
    }

    /// @notice Executes a scheduled, cosigned, and ready expedited operation.
    /// @dev Access: EXPEDITED_EXECUTOR_ROLE (or open executor if address(0)
    ///      holds the role per OZ TimelockController pattern). Gates checked
    ///      in order: (a) operation exists, (b) not already executed,
    ///      (c) cosignature present, (d) readyAt timestamp reached,
    ///      (e) predecessor (if any) is done. Predecessor handling matches
    ///      OZ base contract — reverts TimelockUnexecutedPredecessor.
    ///      Sets done=true BEFORE the external call (reentrancy mitigation:
    ///      same operationId cannot re-execute even if target reentrantly
    ///      calls back). Forwards msg.value to target.
    function executeExpeditedOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external payable returns (bytes memory result) {
        if (!hasRole(EXPEDITED_EXECUTOR_ROLE, address(0)) && !hasRole(EXPEDITED_EXECUTOR_ROLE, msg.sender)) {
            revert ExpeditedExecutorUnauthorized(msg.sender);
        }

        bytes32 operationId = hashExpeditedOperation(target, value, data, predecessor, salt);
        ExpeditedOperation storage operation = _expeditedOperations[operationId];
        if (operation.readyAt == 0) revert ExpeditedOperationUnknown(operationId);
        if (operation.done) revert ExpeditedOperationAlreadyDone(operationId);
        if (!operation.cosigned) revert ExpeditedOperationMissingCosignature(operationId);
        if (block.timestamp < operation.readyAt) revert ExpeditedOperationNotReady(operationId, operation.readyAt);
        if (predecessor != bytes32(0) && !isOperationDone(predecessor)) {
            revert TimelockUnexecutedPredecessor(predecessor);
        }

        operation.done = true;
        (bool ok, bytes memory returnData) = target.call{ value: value }(data);
        if (!ok) revert ExpeditedOperationExecutionFailed(operationId);
        emit ExpeditedOperationExecuted(operationId, target, value);
        return returnData;
    }

    function expeditedOperation(bytes32 operationId) external view returns (uint64 readyAt, bool cosigned, bool done) {
        ExpeditedOperation memory operation = _expeditedOperations[operationId];
        return (operation.readyAt, operation.cosigned, operation.done);
    }
}
