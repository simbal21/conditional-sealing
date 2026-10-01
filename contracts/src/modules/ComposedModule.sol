// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IComposedModule } from "../engine/IConditionEngine.sol";
import { ConditionModuleBase } from "./PaymentObligationModule.sol";

/// @title ComposedModule - boolean composition over child condition modules
/// @notice The "meta-module" of the 9 ConditionEngine modules. Combines child
///         module evaluations with boolean operators (AND / OR / NOT) to build
///         compound predicates like "(payment_default AND time_window) OR
///         court_order" — drives complex use cases: regulator-overrideable
///         reveal, multi-factor enforcement, deferred-trigger M&A escrow,
///         compositional ZPO §371a evidentiary chains.
/// @dev Bounded recursion: MAX_DEPTH=4 prevents stack-exhaustion / gas-DoS
///      via nested composition trees; MAX_CHILDREN=16 bounds per-node fanout.
///      OP_NOT requires exactly 1 child; OP_AND/OP_OR require ≥ 2 children.
///      Child results are populated by setChildResult (CE-only); ComposedModule
///      does NOT itself dispatch to children — the ConditionEngine drives each
///      child module independently then pushes results here for aggregation.
contract ComposedModule is ConditionModuleBase, IComposedModule {
    uint8 public constant OP_AND = 1;
    uint8 public constant OP_OR = 2;
    uint8 public constant OP_NOT = 3;
    uint16 public constant MAX_CHILDREN = 16;
    uint16 public constant MAX_DEPTH = 4;

    struct CompositionState {
        bytes32 compositionRoot;
        uint8 op;
        uint16 depth;
        bytes32[] childRefs;
        bool[] childResults;
        bool terminal;
    }

    mapping(bytes32 => CompositionState) private _compositions;

    /// @dev Locks the implementation so it can only be initialized behind a proxy (audit F-01).
    constructor() {
        _disableInitializers();
    }

    function initialize(address timelock, address conditionEngine) external initializer {
        __ConditionModuleBase_init(timelock, conditionEngine);
    }

    /// @notice Configures a composition node (AND/OR/NOT) over child predicates.
    /// @dev Access: onlyConditionEngineOrModuleAdmin. Invariants enforced in
    ///      _storeComposition: childRefs.length == childResults.length,
    ///      childRefs.length in [1, MAX_CHILDREN]; OP_NOT MUST have exactly 1
    ///      child; OP_AND/OP_OR MUST have ≥ 2 children; depth in [1, MAX_DEPTH].
    ///      Re-configuration deletes old childRefs/childResults arrays before
    ///      pushing new — clean overwrite, no leftover state.
    function configureComposition(
        bytes32 authorizationId,
        bytes32 compositionRoot,
        uint8 op,
        bytes32[] calldata childRefs,
        bool[] calldata childResults,
        uint16 depth,
        bytes32 configDigest
    ) external onlyConditionEngineOrModuleAdmin {
        _storeComposition(authorizationId, compositionRoot, op, childRefs, childResults, depth, configDigest);
    }

    /// @notice Records a sub-module evaluation result into the composed predicate.
    /// @dev Contract-only (onlyConditionEngine). ComposedModule is the meta-module
    ///      that composes other condition modules via boolean operators (AND/OR/etc.)
    ///      per the configured `op`. Children evaluate independently; their results
    ///      are gathered here, then evaluateComposed applies the operator over them.
    /// @param authorizationId target PDA authorization.
    /// @param index child index (must be < childRefs.length set at configure time).
    /// @param result child's evaluated boolean outcome.
    function setChildResult(bytes32 authorizationId, uint256 index, bool result) external onlyConditionEngine {
        _requireKnown(authorizationId);
        if (index >= _compositions[authorizationId].childResults.length) {
            uint16 reportedIndex = type(uint16).max;
            if (index <= type(uint16).max) {
                // forge-lint: disable-next-line(unsafe-typecast)
                reportedIndex = uint16(index);
            }
            revert ComposedChildCountInvalid(authorizationId, reportedIndex);
        }
        _compositions[authorizationId].childResults[index] = result;
    }

    /// @notice Returns whether the composed predicate currently evaluates true.
    /// @dev View. Aggregates the stored childResults with the configured op.
    ///      Returns false for any unknown op (defensive default). Does NOT
    ///      re-run child evaluations — assumes setChildResult has been called
    ///      for each child by the ConditionEngine.
    function evaluateComposed(bytes32 authorizationId) external view returns (bool) {
        return _evaluateModule(authorizationId, bytes32(0));
    }

    /// @notice Returns the full composition state for indexer/auditor inspection.
    /// @dev View. Reverts if unknown. Exposes compositionRoot, op, childRefs/Results,
    ///      depth, terminal flag. Useful for off-chain validators that need to
    ///      reproduce the boolean evaluation and verify against compositionRoot.
    function compositionState(bytes32 authorizationId) external view returns (CompositionState memory) {
        _requireKnown(authorizationId);
        return _compositions[authorizationId];
    }

    function _configureModule(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config, bytes32 configDigest)
        internal
        override
    {
        (uint8 op, bytes32[] memory childRefs, bool[] memory childResults, uint16 depth) =
            abi.decode(config, (uint8, bytes32[], bool[], uint16));
        _storeComposition(authorizationId, moduleRef, op, childRefs, childResults, depth, configDigest);
    }

    function _advanceModule(bytes32 authorizationId, bytes32, bytes calldata) internal override returns (bool) {
        bool result = _evaluateModule(authorizationId, bytes32(0));
        if (!result) revert ComposedChildFalse(authorizationId, bytes32(0));
        _compositions[authorizationId].terminal = true;
        emit ComposedConditionMet(authorizationId, _compositions[authorizationId].compositionRoot);
        return true;
    }

    function _evaluateModule(bytes32 authorizationId, bytes32) internal view override returns (bool) {
        CompositionState storage state = _compositions[authorizationId];
        if (state.op == OP_NOT) return !state.childResults[0];
        if (state.op == OP_AND) {
            for (uint256 i = 0; i < state.childResults.length; ++i) {
                if (!state.childResults[i]) return false;
            }
            return true;
        }
        if (state.op == OP_OR) {
            for (uint256 i = 0; i < state.childResults.length; ++i) {
                if (state.childResults[i]) return true;
            }
            return false;
        }
        return false;
    }

    function _storeComposition(
        bytes32 authorizationId,
        bytes32 compositionRoot,
        uint8 op,
        bytes32[] memory childRefs,
        bool[] memory childResults,
        uint16 depth,
        bytes32 configDigest
    ) private {
        if (childRefs.length != childResults.length || childRefs.length == 0 || childRefs.length > MAX_CHILDREN) {
            revert ComposedChildCountInvalid(authorizationId, uint16(childRefs.length));
        }
        if (op == OP_NOT && childRefs.length != 1) {
            revert ComposedChildCountInvalid(authorizationId, uint16(childRefs.length));
        }
        if (op != OP_NOT && childRefs.length < 2) {
            revert ComposedChildCountInvalid(authorizationId, uint16(childRefs.length));
        }
        if (depth == 0 || depth > MAX_DEPTH) revert ComposedDepthExceeded(authorizationId, depth);
        _moduleConfigs[authorizationId] =
            ModuleConfig({ configured: true, moduleRef: compositionRoot, configDigest: configDigest });
        CompositionState storage state = _compositions[authorizationId];
        delete state.childRefs;
        delete state.childResults;
        state.compositionRoot = compositionRoot;
        state.op = op;
        state.depth = depth;
        state.terminal = false;
        for (uint256 i = 0; i < childRefs.length; ++i) {
            state.childRefs.push(childRefs[i]);
            state.childResults.push(childResults[i]);
        }
        emit ModuleConfigured(authorizationId, compositionRoot, configDigest);
    }

    uint256[50] private __gap;
}
