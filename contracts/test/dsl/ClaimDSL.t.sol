// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";

import { ClaimDSL } from "../../src/dsl/ClaimDSL.sol";
import { IClaimDSL } from "../../src/engine/IConditionEngine.sol";
import { DSLVersionRegistry } from "../../src/registries/DSLVersionRegistry.sol";
import { DeprecationFlag } from "../../src/lib/Structs.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract ClaimDSLTest is Test {
    ClaimDSL internal dsl;
    DSLVersionRegistry internal registry;

    address internal timelock = address(this);
    address internal securityCouncil = address(0xB0B);
    address internal emergencyGovernance = address(0xCAFE);
    address internal pauser = address(0xDA7A);
    bytes32 internal constant DSL_OFF = keccak256("dsl.off");
    bytes32 internal constant DSL_ON = keccak256("dsl.on");
    bytes32 internal constant CAP = keccak256("cap");
    bytes32 internal constant PATH_X = keccak256("path.x");
    bytes32 internal constant PATH_B = keccak256("path.bool");
    bytes32 internal constant CTX = keccak256("ctx");

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(100);
        registry = DSLVersionRegistry(
            ProxyDeploy.deployProxy(
                address(new DSLVersionRegistry()),
                abi.encodeCall(DSLVersionRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser))
            )
        );
        dsl = ClaimDSL(
            ProxyDeploy.deployProxy(
                address(new ClaimDSL()), abi.encodeCall(ClaimDSL.initialize, (timelock, address(registry)))
            )
        );

        registry.addDSLVersion(DSL_OFF, _entry(false));
        registry.addDSLVersion(DSL_ON, _entry(true));
        dsl.setCaps(
            CAP, ClaimDSL.Caps({ maxNodes: 64, maxDepth: 16, maxInSetSize: 8, maxPathDepth: 4, maxEvaluationGas: 0 })
        );
        dsl.registerContextUint(CTX, PATH_X, 10);
        dsl.registerContextBool(CTX, PATH_B, true);
    }

    function test_allTwelveOperators_PositiveAndNegative() external {
        _assertCompare(dsl.OP_EQ(), 10, true);
        _assertCompare(dsl.OP_EQ(), 11, false);
        _assertCompare(dsl.OP_NE(), 11, true);
        _assertCompare(dsl.OP_LT(), 11, true);
        _assertCompare(dsl.OP_LTE(), 10, true);
        _assertCompare(dsl.OP_GT(), 9, true);
        _assertCompare(dsl.OP_GTE(), 10, true);

        assertTrue(_evalBoolPair(dsl.OP_AND(), true, true));
        assertFalse(_evalBoolPair(dsl.OP_AND(), true, false));
        assertTrue(_evalBoolPair(dsl.OP_OR(), false, true));
        assertFalse(_evalBoolPair(dsl.OP_NOT(), true, false));

        bytes32 setRef = keccak256("set");
        bytes32[] memory members = new bytes32[](1);
        members[0] = bytes32(uint256(10));
        dsl.registerSet(setRef, members);
        ClaimDSL.ClaimNode[] memory inNodes = new ClaimDSL.ClaimNode[](2);
        inNodes[0] = ClaimDSL.ClaimNode({ op: dsl.OP_PATH_ACCESS(), left: 0, right: 0, valueRef: PATH_X, aux: 1 });
        inNodes[1] = ClaimDSL.ClaimNode({ op: dsl.OP_IN(), left: 0, right: 0, valueRef: setRef, aux: 0 });
        bytes32 inClaim = keccak256("in");
        dsl.registerClaim(inClaim, inNodes, 1);
        assertTrue(dsl.evaluateClaim(DSL_OFF, inClaim, CTX));

        ClaimDSL.ClaimNode[] memory timeNodes = new ClaimDSL.ClaimNode[](1);
        timeNodes[0] = ClaimDSL.ClaimNode({
            op: dsl.OP_WITHIN_TIME_WINDOW(),
            left: 0,
            right: 0,
            valueRef: bytes32(uint256(block.timestamp - 1)),
            aux: uint32(block.timestamp + 1)
        });
        bytes32 timeClaim = keccak256("time");
        dsl.registerClaim(timeClaim, timeNodes, 0);
        assertTrue(dsl.evaluateClaim(DSL_OFF, timeClaim, CTX));
    }

    function test_customPredicate_ReservedUntilRegistryEnables() external {
        ClaimDSL.ClaimNode[] memory nodes = new ClaimDSL.ClaimNode[](1);
        bytes32 wasmHash = keccak256("wasm");
        nodes[0] = ClaimDSL.ClaimNode({ op: dsl.OP_CUSTOM_PREDICATE(), left: 0, right: 0, valueRef: wasmHash, aux: 0 });
        bytes32 claim = keccak256("custom");
        dsl.registerClaim(claim, nodes, 0);

        vm.expectRevert(abi.encodeWithSelector(IClaimDSL.DSLCustomPredicateReserved.selector, wasmHash));
        dsl.evaluateClaim(DSL_OFF, claim, CTX);

        assertTrue(dsl.evaluateClaim(DSL_ON, claim, CTX));
    }

    function test_typeMismatchAndNodeBudgetRevert() external {
        ClaimDSL.ClaimNode[] memory nodes = new ClaimDSL.ClaimNode[](2);
        nodes[0] = ClaimDSL.ClaimNode({ op: dsl.OP_PATH_ACCESS(), left: 0, right: 0, valueRef: PATH_B, aux: 1 });
        nodes[1] = ClaimDSL.ClaimNode({ op: dsl.OP_EQ(), left: 0, right: 0, valueRef: bytes32(uint256(1)), aux: 0 });
        bytes32 claim = keccak256("mismatch");
        dsl.registerClaim(claim, nodes, 1);
        vm.expectRevert(abi.encodeWithSelector(IClaimDSL.DSLTypeMismatch.selector, uint16(1)));
        dsl.evaluateClaim(DSL_OFF, claim, CTX);

        dsl.setCaps(
            CAP, ClaimDSL.Caps({ maxNodes: 1, maxDepth: 16, maxInSetSize: 8, maxPathDepth: 4, maxEvaluationGas: 0 })
        );
        vm.expectRevert(abi.encodeWithSelector(IClaimDSL.DSLGasBudgetExceeded.selector, claim));
        dsl.evaluateClaim(DSL_OFF, claim, CTX);
    }

    function _assertCompare(uint8 op, uint256 rhs, bool expected) private {
        ClaimDSL.ClaimNode[] memory nodes = new ClaimDSL.ClaimNode[](2);
        nodes[0] = ClaimDSL.ClaimNode({ op: dsl.OP_PATH_ACCESS(), left: 0, right: 0, valueRef: PATH_X, aux: 1 });
        nodes[1] = ClaimDSL.ClaimNode({ op: op, left: 0, right: 0, valueRef: bytes32(rhs), aux: 0 });
        bytes32 claim = keccak256(abi.encode(op, rhs));
        dsl.registerClaim(claim, nodes, 1);
        assertEq(dsl.evaluateClaim(DSL_OFF, claim, CTX), expected);
    }

    function _evalBoolPair(uint8 op, bool leftValue, bool rightValue) private returns (bool) {
        bytes32 leftPath = keccak256(abi.encode("left", op, leftValue, rightValue));
        bytes32 rightPath = keccak256(abi.encode("right", op, leftValue, rightValue));
        dsl.registerContextBool(CTX, leftPath, leftValue);
        dsl.registerContextBool(CTX, rightPath, rightValue);
        ClaimDSL.ClaimNode[] memory nodes = new ClaimDSL.ClaimNode[](3);
        nodes[0] = ClaimDSL.ClaimNode({ op: dsl.OP_PATH_ACCESS(), left: 0, right: 0, valueRef: leftPath, aux: 1 });
        nodes[1] = ClaimDSL.ClaimNode({ op: dsl.OP_PATH_ACCESS(), left: 0, right: 0, valueRef: rightPath, aux: 1 });
        nodes[2] = ClaimDSL.ClaimNode({ op: op, left: 0, right: 1, valueRef: 0, aux: 0 });
        bytes32 claim = keccak256(abi.encode("bool", op, leftValue, rightValue));
        dsl.registerClaim(claim, nodes, 2);
        return dsl.evaluateClaim(DSL_OFF, claim, CTX);
    }

    function _entry(bool customPredicateEnabled) private view returns (DSLVersionRegistry.DSLVersionEntry memory) {
        return DSLVersionRegistry.DSLVersionEntry({
            interpreter: address(dsl),
            capSetHash: CAP,
            customPredicateEnabled: customPredicateEnabled,
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: _zeroFlag(),
            isCanonical: true
        });
    }

    function _zeroFlag() private pure returns (DeprecationFlag memory) {
        return DeprecationFlag({
            deprecated: false,
            deprecationBlockTimestamp: 0,
            deprecationReasonCode: 0,
            disclosureCid: 0,
            disclosureCommitHash: 0,
            disclosureVerifiedBlock: 0,
            autoClearTimestamp: 0,
            isCanonicalAtSet: false
        });
    }
}
