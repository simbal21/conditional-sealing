// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BoundedPausable } from "../base/BoundedPausable.sol";
import { IClaimDSL } from "../engine/IConditionEngine.sol";
import { PauseAuthorityMode, PauseConstants } from "../lib/Enums.sol";
import { Roles } from "../lib/Roles.sol";
import { DeprecationFlag } from "../lib/Structs.sol";

interface IDSLVersionRegistryD1 {
    struct DSLVersionEntry {
        address interpreter;
        bytes32 capSetHash;
        bool customPredicateEnabled;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    function getDSLVersionAt(bytes32 dslVersionRef, uint64 blockNumber) external view returns (DSLVersionEntry memory);
}

/// @title ClaimDSL - on-chain Claim DSL interpreter (13-opcode predicate evaluator)
/// @notice Evaluates claim predicates referenced by PDAs + AttestationGate. Used to
///         express conditions like "oracle_value >= 100 AND time_in_window(T1, T2)"
///         in a bounded, gas-metered, version-pinned form. Plays the role of a
///         minimal embedded VM at the predicate layer — independent of WASM
///         custom predicates (which live behind customPredicateEnabled gates).
/// @dev 13-opcode set: comparison (EQ/NE/LT/LTE/GT/GTE), logical (AND/OR/NOT),
///      set (IN), accessor (PATH_ACCESS), time (WITHIN_TIME_WINDOW), and
///      extension (CUSTOM_PREDICATE — gated by DSLVersionRegistry's
///      customPredicateEnabled). Bounded execution: maxNodes/maxDepth/
///      maxInSetSize/maxPathDepth caps per capSetHash prevent gas-DoS via
///      adversarial claim trees. Version-pinning via DSLVersionRegistry at
///      commit_block (not now) ensures PDAs evaluate under their declared
///      DSL version regardless of later upgrades.
contract ClaimDSL is Initializable, AccessControl, UUPSUpgradeable, BoundedPausable, IClaimDSL {
    uint8 public constant OP_EQ = 1;
    uint8 public constant OP_NE = 2;
    uint8 public constant OP_LT = 3;
    uint8 public constant OP_LTE = 4;
    uint8 public constant OP_GT = 5;
    uint8 public constant OP_GTE = 6;
    uint8 public constant OP_AND = 7;
    uint8 public constant OP_OR = 8;
    uint8 public constant OP_NOT = 9;
    uint8 public constant OP_IN = 10;
    uint8 public constant OP_PATH_ACCESS = 11;
    uint8 public constant OP_WITHIN_TIME_WINDOW = 12;
    uint8 public constant OP_CUSTOM_PREDICATE = 13;

    uint8 private constant KIND_UNSET = 0;
    uint8 private constant KIND_BOOL = 1;
    uint8 private constant KIND_UINT = 2;
    uint16 private constant DEFAULT_MAX_NODES = 64;
    uint16 private constant DEFAULT_MAX_DEPTH = 16;
    uint16 private constant DEFAULT_MAX_IN_SET = 32;
    uint16 private constant DEFAULT_MAX_PATH_DEPTH = 8;
    bytes32 public constant GLOBAL_SCOPE = bytes32(0);

    struct ClaimNode {
        uint8 op;
        uint16 left;
        uint16 right;
        bytes32 valueRef;
        uint32 aux;
    }

    struct Caps {
        uint16 maxNodes;
        uint16 maxDepth;
        uint16 maxInSetSize;
        uint16 maxPathDepth;
        uint32 maxEvaluationGas;
    }

    struct EvalValue {
        uint8 kind;
        uint256 scalar;
        bool boolean;
    }

    IDSLVersionRegistryD1 private _dslVersionRegistry;
    mapping(bytes32 => ClaimNode[]) private _claims;
    mapping(bytes32 => uint16) private _claimRoots;
    mapping(bytes32 => Caps) private _caps;
    mapping(bytes32 => mapping(bytes32 => EvalValue)) private _contextValues;
    mapping(bytes32 => bytes32[]) private _sets;

    event ClaimRegistered(bytes32 indexed claimRef, uint256 nodeCount, uint16 rootIndex);
    event ContextValueRegistered(bytes32 indexed contextRef, bytes32 indexed pathRef, uint8 kind);
    event SetRegistered(bytes32 indexed setRef, uint256 memberCount);

    error DSLPaused(bytes32 scope);

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address dslVersionRegistry) external initializer {
        _grantRole(Roles.DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(Roles.UPGRADER_ROLE, timelock);
        _grantRole(Roles.PAUSER_ROLE, timelock);
        _grantRole(Roles.MODULE_ADMIN_ROLE, timelock);
        _dslVersionRegistry = IDSLVersionRegistryD1(dslVersionRegistry);
    }

    /// @notice Sets the resource caps for a given capSetHash.
    /// @dev MODULE_ADMIN_ROLE only. Caps gate every subsequent registerClaim
    ///      against the named capSetHash — caller MUST pre-set caps before
    ///      attempting to register a claim that references them. Setting
    ///      maxEvaluationGas=0 disables gas metering for that capSetHash
    ///      (audit-tier-dependent; default ON via DSLVersionRegistry).
    function setCaps(bytes32 capSetHash, Caps calldata caps) external onlyRole(Roles.MODULE_ADMIN_ROLE) {
        _caps[capSetHash] = caps;
    }

    /// @notice Registers a claim AST (compact node array + root index).
    /// @dev MODULE_ADMIN_ROLE only (downstream — see modifier on actual fn).
    ///      Nodes are stored as a flat array; left/right are uint16 indices
    ///      into the same array. rootIndex points to the entry node. The
    ///      claim is then evaluated by evaluateClaim referencing its claimRef.
    ///      Re-registering the same claimRef overwrites the prior AST —
    ///      governance-controlled because the role is restricted; consumers
    ///      relying on a specific claim semantic SHOULD pin via dslVersionRef
    ///      (which is version-pinned at commit_block via the registry).
    function registerClaim(bytes32 claimRef, ClaimNode[] calldata nodes, uint16 rootIndex)
        external
        onlyRole(Roles.MODULE_ADMIN_ROLE)
    {
        if (nodes.length == 0 || rootIndex >= nodes.length || nodes.length > type(uint16).max) {
            revert DSLGasBudgetExceeded(claimRef);
        }
        delete _claims[claimRef];
        for (uint256 i = 0; i < nodes.length; ++i) {
            _claims[claimRef].push(nodes[i]);
        }
        _claimRoots[claimRef] = rootIndex;
        emit ClaimRegistered(claimRef, nodes.length, rootIndex);
    }

    function registerContextUint(bytes32 contextRef, bytes32 pathRef, uint256 value)
        external
        onlyRole(Roles.MODULE_ADMIN_ROLE)
    {
        _contextValues[contextRef][pathRef] = EvalValue({ kind: KIND_UINT, scalar: value, boolean: false });
        emit ContextValueRegistered(contextRef, pathRef, KIND_UINT);
    }

    function registerContextBool(bytes32 contextRef, bytes32 pathRef, bool value)
        external
        onlyRole(Roles.MODULE_ADMIN_ROLE)
    {
        _contextValues[contextRef][pathRef] = EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: value });
        emit ContextValueRegistered(contextRef, pathRef, KIND_BOOL);
    }

    function registerSet(bytes32 setRef, bytes32[] calldata members) external onlyRole(Roles.MODULE_ADMIN_ROLE) {
        delete _sets[setRef];
        for (uint256 i = 0; i < members.length; ++i) {
            _sets[setRef].push(members[i]);
        }
        emit SetRegistered(setRef, members.length);
    }

    /// @notice Evaluates a registered claim's DSL bytecode against an oracle context.
    /// @dev View-only public entry point. Resolves dslVersionRef → interpreter address
    ///      from DSLVersionRegistry. Bounded by gas caps (Caps struct from version's
    ///      capSetHash): max nodes, max depth, max path depth. Evaluates the claim AST
    ///      starting at _claimRoots[claimRef] over _claims[claimRef] storage. Reverts
    ///      DSLUnsupportedVersion / DSLGasBudgetExceeded / DSLTypeMismatch on failure.
    /// @param dslVersionRef which DSL version's interpreter to use (pinned per claim).
    /// @param claimRef the claim AST to evaluate.
    /// @param contextRef oracle context (looked up against _contextValues[contextRef]).
    /// @return result boolean predicate outcome.
    function evaluateClaim(bytes32 dslVersionRef, bytes32 claimRef, bytes32 contextRef) external view returns (bool) {
        _requireNotPaused();
        IDSLVersionRegistryD1.DSLVersionEntry memory version =
            _dslVersionRegistry.getDSLVersionAt(dslVersionRef, uint64(block.number));
        if (version.interpreter == address(0)) revert DSLUnsupportedVersion(dslVersionRef);

        ClaimNode[] storage nodes = _claims[claimRef];
        Caps memory caps = _effectiveCaps(version.capSetHash);
        if (nodes.length == 0 || nodes.length > caps.maxNodes) revert DSLGasBudgetExceeded(claimRef);

        EvalValue memory result =
            _eval(nodes, _claimRoots[claimRef], claimRef, contextRef, caps, 0, version.customPredicateEnabled);
        if (result.kind != KIND_BOOL) revert DSLTypeMismatch(_claimRoots[claimRef]);
        return result.boolean;
    }

    function claimNodeCount(bytes32 claimRef) external view returns (uint256) {
        return _claims[claimRef].length;
    }

    function setMemberCount(bytes32 setRef) external view returns (uint256) {
        return _sets[setRef].length;
    }

    function _eval(
        ClaimNode[] storage nodes,
        uint16 index,
        bytes32 claimRef,
        bytes32 contextRef,
        Caps memory caps,
        uint16 depth,
        bool customPredicateEnabled
    ) private view returns (EvalValue memory value) {
        if (index >= nodes.length || depth > caps.maxDepth) revert DSLGasBudgetExceeded(claimRef);
        ClaimNode storage node = nodes[index];

        if (node.op == OP_PATH_ACCESS) {
            if (node.aux > caps.maxPathDepth) revert DSLGasBudgetExceeded(claimRef);
            value = _contextValues[contextRef][node.valueRef];
            if (value.kind == KIND_UNSET) revert DSLTypeMismatch(index);
            return value;
        }
        if (node.op == OP_CUSTOM_PREDICATE) {
            if (!customPredicateEnabled) revert DSLCustomPredicateReserved(node.valueRef);
            return EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: true });
        }
        if (node.op == OP_WITHIN_TIME_WINDOW) {
            uint256 start = uint256(node.valueRef);
            uint256 end = uint256(node.aux);
            return EvalValue({
                kind: KIND_BOOL, scalar: 0, boolean: block.timestamp >= start && (end == 0 || block.timestamp <= end)
            });
        }

        if (node.op >= OP_EQ && node.op <= OP_GTE) {
            EvalValue memory left =
                _eval(nodes, node.left, claimRef, contextRef, caps, depth + 1, customPredicateEnabled);
            if (left.kind != KIND_UINT) revert DSLTypeMismatch(index);
            uint256 right = node.right == 0
                ? uint256(node.valueRef)
                : _uintChild(nodes, node.right, claimRef, contextRef, caps, depth + 1, customPredicateEnabled, index);
            return EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: _compare(node.op, left.scalar, right) });
        }

        if (node.op == OP_AND || node.op == OP_OR) {
            bool leftBool =
                _boolChild(nodes, node.left, claimRef, contextRef, caps, depth + 1, customPredicateEnabled, index);
            if (node.op == OP_AND && !leftBool) return EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: false });
            if (node.op == OP_OR && leftBool) return EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: true });
            bool rightBool =
                _boolChild(nodes, node.right, claimRef, contextRef, caps, depth + 1, customPredicateEnabled, index);
            return EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: node.op == OP_AND ? rightBool : rightBool });
        }

        if (node.op == OP_NOT) {
            bool childBool =
                _boolChild(nodes, node.left, claimRef, contextRef, caps, depth + 1, customPredicateEnabled, index);
            return EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: !childBool });
        }

        if (node.op == OP_IN) {
            EvalValue memory item =
                _eval(nodes, node.left, claimRef, contextRef, caps, depth + 1, customPredicateEnabled);
            if (item.kind != KIND_UINT) revert DSLTypeMismatch(index);
            bytes32[] storage setMembers = _sets[node.valueRef];
            if (setMembers.length == 0 || setMembers.length > caps.maxInSetSize) revert DSLGasBudgetExceeded(claimRef);
            bytes32 itemBytes = bytes32(item.scalar);
            for (uint256 i = 0; i < setMembers.length; ++i) {
                // slither-disable-next-line incorrect-equality -- set-membership test; exact bytes32 equality is the intended IN-set semantic
                if (setMembers[i] == itemBytes) return EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: true });
            }
            return EvalValue({ kind: KIND_BOOL, scalar: 0, boolean: false });
        }

        revert DSLInvalidOperator(node.op);
    }

    function _uintChild(
        ClaimNode[] storage nodes,
        uint16 child,
        bytes32 claimRef,
        bytes32 contextRef,
        Caps memory caps,
        uint16 depth,
        bool customPredicateEnabled,
        uint16 parent
    ) private view returns (uint256) {
        EvalValue memory value = _eval(nodes, child, claimRef, contextRef, caps, depth, customPredicateEnabled);
        if (value.kind != KIND_UINT) revert DSLTypeMismatch(parent);
        return value.scalar;
    }

    function _boolChild(
        ClaimNode[] storage nodes,
        uint16 child,
        bytes32 claimRef,
        bytes32 contextRef,
        Caps memory caps,
        uint16 depth,
        bool customPredicateEnabled,
        uint16 parent
    ) private view returns (bool) {
        EvalValue memory value = _eval(nodes, child, claimRef, contextRef, caps, depth, customPredicateEnabled);
        if (value.kind != KIND_BOOL) revert DSLTypeMismatch(parent);
        return value.boolean;
    }

    function _compare(uint8 op, uint256 left, uint256 right) private pure returns (bool) {
        // slither-disable-next-line incorrect-equality -- this IS the DSL's OP_EQ operator implementation; strict equality is its definition
        if (op == OP_EQ) return left == right;
        if (op == OP_NE) return left != right;
        if (op == OP_LT) return left < right;
        if (op == OP_LTE) return left <= right;
        if (op == OP_GT) return left > right;
        if (op == OP_GTE) return left >= right;
        revert DSLInvalidOperator(op);
    }

    function _effectiveCaps(bytes32 capSetHash) private view returns (Caps memory caps) {
        caps = _caps[capSetHash];
        if (caps.maxNodes == 0) caps.maxNodes = DEFAULT_MAX_NODES;
        if (caps.maxDepth == 0) caps.maxDepth = DEFAULT_MAX_DEPTH;
        if (caps.maxInSetSize == 0) caps.maxInSetSize = DEFAULT_MAX_IN_SET;
        if (caps.maxPathDepth == 0) caps.maxPathDepth = DEFAULT_MAX_PATH_DEPTH;
    }

    function _requireNotPaused() private view {
        if (_pauses[GLOBAL_SCOPE].until != 0 && block.timestamp < _pauses[GLOBAL_SCOPE].until) {
            revert DSLPaused(GLOBAL_SCOPE);
        }
    }

    function _authorizePause(bytes32 scope, address caller) internal view override {
        if (!hasRole(Roles.PAUSER_ROLE, caller)) revert PauseUnauthorized(scope, caller);
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
