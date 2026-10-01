// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IMultiPartySignalModule } from "../../src/engine/IConditionEngine.sol";
import { MultiPartySignalModule } from "../../src/modules/MultiPartySignalModule.sol";
import { ModuleTestBase } from "./PaymentObligationModule.t.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract MultiPartySignalModuleTest is ModuleTestBase {
    MultiPartySignalModule internal module;
    bytes32 internal signalDigest = keccak256("signal");
    bytes32 internal wrongSignalDigest = keccak256("wrong-signal");

    // SC-F-06: signers must be real keypairs so the module can recover the EIP-712 signer.
    uint256 internal pkA = 0xA11CE;
    uint256 internal pkB = 0xB0B;
    address internal signerA;
    address internal signerB;

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisMultiPartySignal");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    bytes32 private constant _SIGNAL_TYPEHASH =
        keccak256("Signal(bytes32 authorizationId,bytes32 signalDigest,address signer)");

    function setUp() public {
        vm.warp(1_000_000);
        signerA = vm.addr(pkA);
        signerB = vm.addr(pkB);
        module = MultiPartySignalModule(
            ProxyDeploy.deployProxy(
                address(new MultiPartySignalModule()),
                abi.encodeCall(MultiPartySignalModule.initialize, (timelock, engine))
            )
        );
        address[] memory signers = new address[](2);
        signers[0] = signerA;
        signers[1] = signerB;
        module.configureSignal(auth, signalDigest, signers, 2, uint64(block.timestamp + 1 days), configDigest);
    }

    function _digest(bytes32 authorizationId, bytes32 sigDigest, address signer) private view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid, address(module)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_SIGNAL_TYPEHASH, authorizationId, sigDigest, signer));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    function _sign(uint256 pk, bytes32 authorizationId, bytes32 sigDigest, address signer)
        private
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _digest(authorizationId, sigDigest, signer));
        return abi.encodePacked(r, s, v);
    }

    function test_thresholdDuplicateAndDigestMismatch() external {
        _assertNoAuthorizationEvents("src/modules/MultiPartySignalModule.sol");
        module.submitSignal(auth, signerA, signalDigest, _sign(pkA, auth, signalDigest, signerA), "");
        vm.expectRevert(
            abi.encodeWithSelector(IMultiPartySignalModule.MultiPartySignalDuplicateSigner.selector, auth, signerA)
        );
        module.submitSignal(auth, signerA, signalDigest, _sign(pkA, auth, signalDigest, signerA), "");

        vm.expectRevert(
            abi.encodeWithSelector(
                IMultiPartySignalModule.MultiPartySignalDigestMismatch.selector, auth, signalDigest, wrongSignalDigest
            )
        );
        module.submitSignal(auth, signerB, wrongSignalDigest, _sign(pkB, auth, wrongSignalDigest, signerB), "");

        vm.expectRevert(
            abi.encodeWithSelector(IMultiPartySignalModule.MultiPartySignalThresholdNotMet.selector, auth, 1, 2)
        );
        module.advance(auth, signalDigest, "");

        module.submitSignal(auth, signerB, signalDigest, _sign(pkB, auth, signalDigest, signerB), "");
        assertTrue(module.advance(auth, signalDigest, ""));
    }

    /// SC-F-06: the trusted caller cannot forge k-of-n by claiming an allow-listed signer
    /// with arbitrary non-empty envelope bytes. Recovery must equal the claimed signer.
    /// FAILS against pre-fix code (which only checked envelope length != 0), PASSES with fix.
    function test_SC_F_06_forgedSignatureRejected() external {
        // Arbitrary 65-byte blob that recovers to some address other than signerA.
        bytes memory junk = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));
        vm.expectRevert(
            abi.encodeWithSelector(IMultiPartySignalModule.MultiPartySignalSignerIneligible.selector, auth, signerA)
        );
        module.submitSignal(auth, signerA, signalDigest, junk, "");

        // signerB signs but the caller claims it counts for signerA → recovery mismatch.
        bytes memory bSig = _sign(pkB, auth, signalDigest, signerA);
        vm.expectRevert(
            abi.encodeWithSelector(IMultiPartySignalModule.MultiPartySignalSignerIneligible.selector, auth, signerA)
        );
        module.submitSignal(auth, signerA, signalDigest, bSig, "");

        // Wrong-chain signature (replay) → digest binds block.chainid, recovery fails.
        bytes32 wrongChainDomain = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid + 1, address(module)
            )
        );
        bytes32 wrongChainStruct = keccak256(abi.encode(_SIGNAL_TYPEHASH, auth, signalDigest, signerA));
        bytes32 wrongChainDigest = keccak256(abi.encodePacked(hex"1901", wrongChainDomain, wrongChainStruct));
        (uint8 wv, bytes32 wr, bytes32 ws) = vm.sign(pkA, wrongChainDigest);
        vm.expectRevert(
            abi.encodeWithSelector(IMultiPartySignalModule.MultiPartySignalSignerIneligible.selector, auth, signerA)
        );
        module.submitSignal(auth, signerA, signalDigest, abi.encodePacked(wr, ws, wv), "");

        // Sanity: a correctly bound signature is still accepted.
        module.submitSignal(auth, signerA, signalDigest, _sign(pkA, auth, signalDigest, signerA), "");
        (uint16 count,) = module.signalCount(auth, signalDigest);
        assertEq(count, 1);
    }

    /// B3a: reconfiguring to remove a signer must drop that signer's eligibility.
    /// FAILS against pre-fix code (eligibility flag never cleared → removed signer still counts),
    /// PASSES with fix (epoch bump clears prior eligibility + counts).
    function test_B3a_reconfigureClearsRemovedSigner() external {
        address signerC = vm.addr(0xC0FFEE);

        // First config: A counted (1 of 2 toward old threshold).
        module.submitSignal(auth, signerA, signalDigest, _sign(pkA, auth, signalDigest, signerA), "");
        (uint16 preCount,) = module.signalCount(auth, signalDigest);
        assertEq(preCount, 1);

        // Reconfigure: remove signerA, keep signerB, add signerC. New threshold 1.
        address[] memory signers = new address[](2);
        signers[0] = signerB;
        signers[1] = signerC;
        module.configureSignal(auth, signalDigest, signers, 1, uint64(block.timestamp + 1 days), configDigest);

        // Old count must be wiped — removed signer's contribution is gone.
        (uint16 postCount,) = module.signalCount(auth, signalDigest);
        assertEq(postCount, 0);

        // The removed signer can no longer submit, even with a valid signature.
        vm.expectRevert(
            abi.encodeWithSelector(IMultiPartySignalModule.MultiPartySignalSignerIneligible.selector, auth, signerA)
        );
        module.submitSignal(auth, signerA, signalDigest, _sign(pkA, auth, signalDigest, signerA), "");

        // A retained/new signer still works under the new epoch.
        module.submitSignal(auth, signerB, signalDigest, _sign(pkB, auth, signalDigest, signerB), "");
        assertTrue(module.advance(auth, signalDigest, ""));
    }
}
