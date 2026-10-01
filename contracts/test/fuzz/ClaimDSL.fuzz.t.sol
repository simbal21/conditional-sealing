// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { ClaimDSL } from "../../src/dsl/ClaimDSL.sol";
import { IClaimDSL } from "../../src/engine/IConditionEngine.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract ClaimDSLFuzzTest is Test {
    ClaimDSL internal dsl;
    address internal timelock = address(0xA11CE);
    address internal admin = address(0xB0B);
    address internal stranger = address(0xCAFE);
    // Mock registry — any address; not invoked in these tests (registerClaim path).
    address internal mockRegistry = address(0xD00D);

    function setUp() public {
        dsl = ClaimDSL(
            ProxyDeploy.deployProxy(
                address(new ClaimDSL()), abi.encodeCall(ClaimDSL.initialize, (timelock, mockRegistry))
            )
        );
        // MODULE_ADMIN_ROLE granted to timelock at init; grant to admin for tests
        vm.prank(timelock);
        dsl.grantRole(Roles.MODULE_ADMIN_ROLE, admin);
        vm.warp(1_000_000);
    }

    /// @notice Fuzz: registerClaim MUST revert DSLGasBudgetExceeded for any empty nodes array.
    function testFuzz_registerClaim_RevertsOnEmptyNodes(bytes32 claimRef, uint16 rootIndex) external {
        ClaimDSL.ClaimNode[] memory empty = new ClaimDSL.ClaimNode[](0);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IClaimDSL.DSLGasBudgetExceeded.selector, claimRef));
        dsl.registerClaim(claimRef, empty, rootIndex);
    }

    /// @notice Fuzz: registerClaim MUST revert DSLGasBudgetExceeded when rootIndex >= nodes.length.
    function testFuzz_registerClaim_RevertsOnRootOutOfBounds(bytes32 claimRef, uint8 nodeCount, uint16 rootIndex)
        external
    {
        uint8 boundedNodeCount = (nodeCount % 10) + 1; // 1..10 nodes
        // Force rootIndex >= nodeCount by adding nodeCount
        uint16 outOfBoundsRoot = uint16(boundedNodeCount) + uint16(rootIndex % 100);
        ClaimDSL.ClaimNode[] memory nodes = new ClaimDSL.ClaimNode[](boundedNodeCount);
        for (uint256 i = 0; i < boundedNodeCount; ++i) {
            nodes[i] = ClaimDSL.ClaimNode({ op: 1, left: 0, right: 0, valueRef: bytes32(0), aux: 0 });
        }
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IClaimDSL.DSLGasBudgetExceeded.selector, claimRef));
        dsl.registerClaim(claimRef, nodes, outOfBoundsRoot);
    }

    /// @notice Fuzz: registerClaim accepts any valid (nodes, rootIndex) tuple.
    function testFuzz_registerClaim_AcceptsValidNodes(bytes32 claimRef, uint8 nodeCount, uint16 rootRaw) external {
        uint8 boundedNodeCount = (nodeCount % 16) + 1; // 1..16 nodes (below MODULE caps)
        uint16 rootIndex = rootRaw % uint16(boundedNodeCount);
        ClaimDSL.ClaimNode[] memory nodes = new ClaimDSL.ClaimNode[](boundedNodeCount);
        for (uint256 i = 0; i < boundedNodeCount; ++i) {
            nodes[i] = ClaimDSL.ClaimNode({ op: 1, left: 0, right: 0, valueRef: bytes32(0), aux: 0 });
        }
        vm.prank(admin);
        dsl.registerClaim(claimRef, nodes, rootIndex);
        // No revert = pass
    }

    /// @notice Fuzz: non-admin caller MUST revert on registerClaim for any args.
    function testFuzz_registerClaim_UnauthorizedRevert(address caller, bytes32 claimRef) external {
        vm.assume(caller != address(0));
        vm.assume(caller != timelock);
        vm.assume(caller != admin);
        ClaimDSL.ClaimNode[] memory nodes = new ClaimDSL.ClaimNode[](1);
        nodes[0] = ClaimDSL.ClaimNode({ op: 1, left: 0, right: 0, valueRef: bytes32(0), aux: 0 });
        vm.prank(caller);
        vm.expectRevert(); // AccessControl rejects
        dsl.registerClaim(claimRef, nodes, 0);
    }

    /// @notice Fuzz: setCaps accepts any (capSetHash, Caps) tuple from MODULE_ADMIN.
    function testFuzz_setCaps_AcceptsAnyValidArgs(
        bytes32 capSetHash,
        uint16 maxNodes,
        uint16 maxDepth,
        uint16 maxInSetSize,
        uint16 maxPathDepth,
        uint32 maxEvalGas
    ) external {
        ClaimDSL.Caps memory caps = ClaimDSL.Caps({
            maxNodes: maxNodes,
            maxDepth: maxDepth,
            maxInSetSize: maxInSetSize,
            maxPathDepth: maxPathDepth,
            maxEvaluationGas: maxEvalGas
        });
        vm.prank(admin);
        dsl.setCaps(capSetHash, caps);
    }

    /// @notice Fuzz: registerContextUint / registerContextBool MUST require MODULE_ADMIN.
    function testFuzz_registerContext_UnauthorizedRevert(
        address caller,
        bytes32 contextRef,
        bytes32 pathRef,
        uint256 value,
        bool boolVal
    ) external {
        vm.assume(caller != address(0));
        vm.assume(caller != timelock);
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert(); // AccessControl rejects
        dsl.registerContextUint(contextRef, pathRef, value);

        vm.prank(caller);
        vm.expectRevert();
        dsl.registerContextBool(contextRef, pathRef, boolVal);
    }
}
