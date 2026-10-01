// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { CealisIdentifierHelpers } from "../../src/helpers/CealisIdentifierHelpers.sol";
import { BoundedPausable } from "../../src/base/BoundedPausable.sol";
import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { ICealisIdentifierHelpers } from "../../src/helpers/ICealisIdentifierHelpers.sol";
import { IPausableSurface } from "../../src/base/IPausableSurface.sol";
import { Tags } from "../../src/lib/Tags.sol";
import { Roles } from "../../src/lib/Roles.sol";
import {
    CeremonyAxis,
    ConditionMode,
    ConditionalRecipientMode,
    G3Choice,
    G4Phase,
    GateKind,
    LifecycleState,
    PauseAuthorityMode,
    PauseConstants,
    ProtocolVersion,
    ShredAuthorityMode,
    ShredState
} from "../../src/lib/Enums.sol";
import {
    AxisConfig,
    DeprecationFlag,
    FSMAdvanceResult,
    HCommitFields,
    LegalFlags,
    PDARegistration,
    PdaRootFields,
    RegistryRefs
} from "../../src/lib/Structs.sol";
import {
    BuildProtocolVersionMismatch,
    LegalEffectHaltOptOutForbidden,
    LegalEffectPhaseInvalid,
    LegalEffectSyncedPasskeyForbidden,
    Mode3Reserved,
    PauseAuthorityInvalid,
    PauseDurationTooLong,
    ShredAuthorityInvalid
} from "../../src/lib/Errors.sol";

/// @title _SizeGateScaffold - PHASE A SCAFFOLD ONLY
/// @notice Internal scaffold ONLY for size measurement.
///         REPLACED IN PHASE D2 BY REAL ConditionEngine.
///
/// @dev This contract imports every Phase A foundation symbol that
///      ConditionEngine will need (registries, modules, FSM, AttestationGate
///      will add ~12-15 more imports in Phase D2). Goal: `forge build --sizes`
///      against this scaffold gives a baseline measurement of import / library
///      / interface overhead, informing Phase D2's R-M2-01 size-gate planning.
///
///      Lives under `test/foundation/` (NOT `src/engine/`) so Phase A respects
///      the no-touch list for Phase D2's territory.
contract _SizeGateScaffold {
    // Touch every Phase A symbol so the compiler can't strip the imports.
    bytes32 public constant TAG_REF = Tags.TAG_COMMIT_V3;
    bytes32 public constant ROLE_REF = Roles.ORCHESTRATOR_ROLE;
    uint64 public constant MAX_PAUSE_REF = PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS;
    uint16 public constant PROTO_REF = ProtocolVersion.BUILD_PROTOCOL_VERSION;

    function noop() external pure returns (uint256) {
        return 0;
    }

    /// @notice Touch every enum / struct / error so the symbol references stick.
    function _scaffold(
        CeremonyAxis _axis,
        ConditionMode _cm,
        ConditionalRecipientMode _crm,
        G3Choice _g3,
        G4Phase _g4,
        GateKind _gk,
        LifecycleState _ls,
        PauseAuthorityMode _pam,
        ShredAuthorityMode _sam,
        ShredState _ss,
        PdaRootFields calldata _prf,
        HCommitFields calldata _hcf,
        AxisConfig calldata _ac,
        RegistryRefs calldata _rr,
        LegalFlags calldata _lf,
        PDARegistration calldata _pdar,
        FSMAdvanceResult calldata _far,
        DeprecationFlag calldata _df,
        ICealisIdentifierHelpers _h,
        IPausableSurface _ps,
        IBaseRegistry _br
    ) external pure returns (bool) {
        _axis;
        _cm;
        _crm;
        _g3;
        _g4;
        _gk;
        _ls;
        _pam;
        _sam;
        _ss;
        _prf;
        _hcf;
        _ac;
        _rr;
        _lf;
        _pdar;
        _far;
        _df;
        _h;
        _ps;
        _br;
        // Touch every cross-cutting error symbol via selectors so the compiler
        // doesn't strip the import.
        bytes4 e1 = Mode3Reserved.selector;
        bytes4 e2 = LegalEffectPhaseInvalid.selector;
        bytes4 e3 = LegalEffectHaltOptOutForbidden.selector;
        bytes4 e4 = LegalEffectSyncedPasskeyForbidden.selector;
        bytes4 e5 = PauseDurationTooLong.selector;
        bytes4 e6 = PauseAuthorityInvalid.selector;
        bytes4 e7 = BuildProtocolVersionMismatch.selector;
        bytes4 e8 = ShredAuthorityInvalid.selector;
        e1;
        e2;
        e3;
        e4;
        e5;
        e6;
        e7;
        e8;
        return true;
    }
}

/// @notice Tiny concrete BoundedPausable used to measure the abstract base's
///         contribution to deployed bytecode. Auth is permissive so the
///         contract is purely a size probe (NOT for production).
contract _BoundedPausableProbe is BoundedPausable {
    function _authorizePause(bytes32, address) internal pure override {
        // permissive - probe only
    }
}

/// @notice Concrete CealisIdentifierHelpers probe so its size is included
///         in `forge build --sizes` baseline output.
contract _IdentifierHelpersProbe is CealisIdentifierHelpers { }
