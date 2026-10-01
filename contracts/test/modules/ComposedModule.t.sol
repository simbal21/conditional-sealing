// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IComposedModule } from "../../src/engine/IConditionEngine.sol";
import { ComposedModule } from "../../src/modules/ComposedModule.sol";
import { ModuleTestBase } from "./PaymentObligationModule.t.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract ComposedModuleTest is ModuleTestBase {
    ComposedModule internal module;
    bytes32 internal root = keccak256("composition");

    function setUp() public {
        module = ComposedModule(
            ProxyDeploy.deployProxy(
                address(new ComposedModule()), abi.encodeCall(ComposedModule.initialize, (timelock, engine))
            )
        );
    }

    function test_andOrNotCompositionAndCaps() external {
        _assertNoAuthorizationEvents("src/modules/ComposedModule.sol");
        bytes32[] memory children = new bytes32[](2);
        bool[] memory results = new bool[](2);
        children[0] = keccak256("a");
        children[1] = keccak256("b");
        results[0] = true;
        results[1] = false;

        module.configureComposition(auth, root, module.OP_AND(), children, results, 1, configDigest);
        assertFalse(module.evaluateComposed(auth));
        module.setChildResult(auth, 1, true);
        assertTrue(module.advance(auth, root, ""));

        bytes32 orAuth = keccak256("or");
        results[0] = false;
        results[1] = true;
        module.configureComposition(orAuth, root, module.OP_OR(), children, results, 1, configDigest);
        assertTrue(module.evaluateComposed(orAuth));

        bytes32 notAuth = keccak256("not");
        bytes32[] memory oneChild = new bytes32[](1);
        bool[] memory oneResult = new bool[](1);
        oneChild[0] = keccak256("only");
        oneResult[0] = false;
        module.configureComposition(notAuth, root, module.OP_NOT(), oneChild, oneResult, 1, configDigest);
        assertTrue(module.evaluateComposed(notAuth));
    }

    function test_childCountAndDepthCaps() external {
        bytes32[] memory oneChild = new bytes32[](1);
        bool[] memory oneResult = new bool[](1);
        oneChild[0] = keccak256("only");
        oneResult[0] = true;

        uint8 andOp = module.OP_AND();
        vm.expectRevert(abi.encodeWithSelector(IComposedModule.ComposedChildCountInvalid.selector, auth, uint16(1)));
        module.configureComposition(auth, root, andOp, oneChild, oneResult, 1, configDigest);

        bytes32[] memory children = new bytes32[](2);
        bool[] memory results = new bool[](2);
        uint8 orOp = module.OP_OR();
        vm.expectRevert(abi.encodeWithSelector(IComposedModule.ComposedDepthExceeded.selector, auth, uint16(5)));
        module.configureComposition(auth, root, orOp, children, results, 5, configDigest);
    }
}
