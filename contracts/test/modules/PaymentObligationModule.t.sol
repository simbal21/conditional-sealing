// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";

import { IConditionModule, IPaymentObligationModule } from "../../src/engine/IConditionEngine.sol";
import { PaymentObligationModule } from "../../src/modules/PaymentObligationModule.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

abstract contract ModuleTestBase is Test {
    address internal timelock = address(this);
    address internal engine = address(this);
    address internal stranger = address(0xBEEF);
    bytes32 internal auth = keccak256("auth");
    bytes32 internal configDigest = keccak256("config");

    function _assertNoAuthorizationEvents(string memory path) internal view {
        string memory source = vm.readFile(path);
        assertFalse(_contains(bytes(source), bytes("RevealAuthorized")), "module source declares reveal emitter");
        assertFalse(_contains(bytes(source), bytes("ShredAuthorized")), "module source declares shred emitter");
    }

    function _contains(bytes memory haystack, bytes memory needle) private pure returns (bool) {
        if (needle.length == 0 || needle.length > haystack.length) return false;
        for (uint256 i = 0; i <= haystack.length - needle.length; ++i) {
            bool matched = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    matched = false;
                    break;
                }
            }
            if (matched) return true;
        }
        return false;
    }
}

contract PaymentObligationModuleTest is ModuleTestBase {
    PaymentObligationModule internal module;
    bytes32 internal obligation = keccak256("obligation");
    bytes32 internal defaultDigest = keccak256("default");

    function setUp() public {
        vm.warp(1_000_000);
        module = PaymentObligationModule(
            ProxyDeploy.deployProxy(
                address(new PaymentObligationModule()),
                abi.encodeCall(PaymentObligationModule.initialize, (timelock, engine))
            )
        );
    }

    function test_paymentDefaultCureWindowAndTripwire() external {
        _assertNoAuthorizationEvents("src/modules/PaymentObligationModule.sol");
        module.configureObligation(auth, obligation, uint64(block.timestamp), 100, 1, configDigest);
        module.markDefaultObserved(obligation, defaultDigest);

        vm.expectRevert(
            abi.encodeWithSelector(IPaymentObligationModule.PaymentObligationCureWindowActive.selector, obligation)
        );
        module.advance(auth, defaultDigest, "");

        vm.warp(block.timestamp + 101);
        assertTrue(module.advance(auth, defaultDigest, ""));
        assertTrue(module.evaluate(auth, bytes32(0)));
    }

    function test_paymentObservationAndUnauthorizedCaller() external {
        module.configureObligation(auth, obligation, uint64(block.timestamp), 100, 1, configDigest);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IConditionModule.ModuleUnauthorizedCaller.selector, stranger));
        module.markPaymentObserved(obligation, keccak256("payment"));

        module.markPaymentObserved(obligation, keccak256("payment"));
        (uint8 status,,) = module.obligationStatus(obligation);
        assertEq(status, 2);
    }
}
