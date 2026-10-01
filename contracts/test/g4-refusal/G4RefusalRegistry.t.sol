// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { G4RefusalRegistry } from "../../src/g4-refusal/G4RefusalRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract G4RefusalRegistryTest is Test {
    G4RefusalRegistry internal registry;

    address internal timelock = address(0x4001);
    address internal operator = address(0x4002);
    bytes32 internal hCommit = keccak256("hCommit");

    event RefusalReasonEncrypted(bytes32 indexed authorizationId, bytes encryptedReasonBlob);
    event AdvisorySignal(bytes32 indexed authorizationId, bytes32 indexed hCommit, uint8 reasonCode);

    function setUp() public {
        registry = G4RefusalRegistry(
            ProxyDeploy.deployProxy(
                address(new G4RefusalRegistry()), abi.encodeCall(G4RefusalRegistry.initialize, (timelock))
            )
        );
        vm.prank(timelock);
        registry.grantRole(Roles.OPERATOR_ROLE, operator);
    }

    function test_allTenCodesUseCorrectSurfaces() external {
        uint8 art17 = registry.REASON_ART_17_ERASURE();
        uint8 art18 = registry.REASON_ART_18_RESTRICTION();
        uint8 optOut = registry.REASON_OPT_OUT_ACTIVE();
        for (uint8 code = 1; code <= 9; ++code) {
            bytes32 auth = bytes32(uint256(code));
            vm.prank(operator);
            if (code == art17 || code == art18) {
                registry.refuseEncrypted(auth, hCommit, code, abi.encodePacked(code));
            } else {
                registry.refusePublic(auth, hCommit, code, bytes32(uint256(code)));
            }
            (bool refused, uint8 reasonCode,) = registry.refusalState(auth);
            assertTrue(refused);
            assertEq(reasonCode, code);
        }

        bytes32 advisoryAuth = bytes32(uint256(10));
        vm.prank(operator);
        registry.recordAdvisorySignal(advisoryAuth, hCommit, optOut);
        (bool signaled, uint8 signalCode) = registry.signalState(advisoryAuth);
        (bool advisoryRefused,,) = registry.refusalState(advisoryAuth);
        assertTrue(signaled);
        assertEq(signalCode, optOut);
        assertFalse(advisoryRefused);
    }

    function test_refusePublicWithAdvisoryCodeReverts() external {
        uint8 optOut = registry.REASON_OPT_OUT_ACTIVE();
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(G4RefusalRegistry.RefusalAdvisoryReasonNotBlocking.selector, optOut));
        registry.refusePublic(keccak256("auth"), hCommit, optOut, bytes32(0));
    }

    function test_recordAdvisorySignalWithBlockingCodeReverts() external {
        uint8 chainMismatch = registry.REASON_CHAIN_MISMATCH();
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(G4RefusalRegistry.RefusalBlockingReasonRequired.selector, chainMismatch));
        registry.recordAdvisorySignal(keccak256("auth"), hCommit, chainMismatch);
    }

    function test_sensitivePublicReasonMustBeEncrypted() external {
        uint8 art17 = registry.REASON_ART_17_ERASURE();
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(G4RefusalRegistry.RefusalSensitiveReasonMustBeEncrypted.selector, art17));
        registry.refusePublic(keccak256("auth"), hCommit, art17, bytes32(0));
    }

    function test_refuseEncryptedWithArt17EmitsEncryptedReason() external {
        bytes32 auth = keccak256("auth");
        bytes memory encrypted = hex"01020304";
        uint8 art17 = registry.REASON_ART_17_ERASURE();
        vm.expectEmit(true, false, false, true);
        emit RefusalReasonEncrypted(auth, encrypted);
        vm.prank(operator);
        registry.refuseEncrypted(auth, hCommit, art17, encrypted);

        (bool refused, uint8 code, bool encryptedMode) = registry.refusalState(auth);
        assertTrue(refused);
        assertEq(code, art17);
        assertTrue(encryptedMode);
    }

    function test_advisoryEmitsAdvisoryOnlyAndDoesNotRefuse() external {
        bytes32 auth = keccak256("advisory");
        uint8 optOut = registry.REASON_OPT_OUT_ACTIVE();
        vm.expectEmit(true, true, false, true);
        emit AdvisorySignal(auth, hCommit, optOut);
        vm.prank(operator);
        registry.recordAdvisorySignal(auth, hCommit, optOut);

        (bool refused,,) = registry.refusalState(auth);
        assertFalse(refused);
    }
}
