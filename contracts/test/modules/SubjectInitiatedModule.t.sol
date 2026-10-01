// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ISubjectInitiatedModule } from "../../src/engine/IConditionEngine.sol";
import { CeremonyAxis } from "../../src/lib/Enums.sol";
import { SubjectInitiatedModule } from "../../src/modules/SubjectInitiatedModule.sol";
import { ModuleTestBase } from "./PaymentObligationModule.t.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract SubjectInitiatedModuleTest is ModuleTestBase {
    SubjectInitiatedModule internal module;
    bytes32 internal action = keccak256("action");

    // SC-F-06: the subject must be a real keypair so the module can recover the EIP-712 signer.
    uint256 internal pkSubject = 0x5AB1EC7;
    address internal subject;

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisSubjectInitiated");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    bytes32 private constant _SUBJECT_ACTION_TYPEHASH =
        keccak256("SubjectAction(bytes32 authorizationId,bytes32 actionDigest,address subject)");

    function setUp() public {
        vm.warp(1_000_000);
        subject = vm.addr(pkSubject);
        module = SubjectInitiatedModule(
            ProxyDeploy.deployProxy(
                address(new SubjectInitiatedModule()),
                abi.encodeCall(SubjectInitiatedModule.initialize, (timelock, engine))
            )
        );
        module.configureSubjectInitiated(auth, CeremonyAxis.Reveal, subject, configDigest);
    }

    function _digest(bytes32 authorizationId, bytes32 actionDigest, address subj) private view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid, address(module)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_SUBJECT_ACTION_TYPEHASH, authorizationId, actionDigest, subj));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    function _sign(uint256 pk, bytes32 authorizationId, bytes32 actionDigest, address subj)
        private
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _digest(authorizationId, actionDigest, subj));
        return abi.encodePacked(r, s, v);
    }

    function test_subjectInitiatedNonceAxisAndExpiry() external {
        _assertNoAuthorizationEvents("src/modules/SubjectInitiatedModule.sol");
        bytes memory sig = _sign(pkSubject, auth, action, subject);

        vm.expectRevert(
            abi.encodeWithSelector(
                ISubjectInitiatedModule.SubjectInitiatedAxisMismatch.selector,
                auth,
                CeremonyAxis.Reveal,
                CeremonyAxis.Shred
            )
        );
        module.submitSubjectInitiated(auth, CeremonyAxis.Shred, action, sig, 1, uint64(block.timestamp + 100));

        module.submitSubjectInitiated(auth, CeremonyAxis.Reveal, action, sig, 1, uint64(block.timestamp + 100));
        assertTrue(module.evaluate(auth, action));

        vm.expectRevert(abi.encodeWithSelector(ISubjectInitiatedModule.SubjectInitiatedNonceConsumed.selector, auth, 1));
        module.submitSubjectInitiated(auth, CeremonyAxis.Reveal, action, sig, 1, uint64(block.timestamp + 100));
    }

    function test_expiredOrEmptySignatureReverts() external {
        bytes memory sig = _sign(pkSubject, auth, action, subject);

        vm.expectRevert(abi.encodeWithSelector(ISubjectInitiatedModule.SubjectInitiatedExpired.selector, auth, 1));
        module.submitSubjectInitiated(auth, CeremonyAxis.Reveal, action, sig, 2, 1);

        // Empty / malformed signature fails closed to address(0) → invalid-signer.
        vm.expectRevert(abi.encodeWithSelector(ISubjectInitiatedModule.SubjectInitiatedInvalidSigner.selector, auth));
        module.submitSubjectInitiated(auth, CeremonyAxis.Reveal, action, "", 2, uint64(block.timestamp + 100));
    }

    /// SC-F-06: the trusted caller cannot forge subject assent with arbitrary non-empty
    /// envelope bytes. Recovery must equal the PDA-configured subject signer.
    /// FAILS against pre-fix code (which only checked envelope length != 0), PASSES with fix.
    function test_SC_F_06_forgedSubjectSignatureRejected() external {
        // Arbitrary 65-byte blob that recovers to some address other than `subject`.
        bytes memory junk = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));
        vm.expectRevert(abi.encodeWithSelector(ISubjectInitiatedModule.SubjectInitiatedInvalidSigner.selector, auth));
        module.submitSubjectInitiated(auth, CeremonyAxis.Reveal, action, junk, 1, uint64(block.timestamp + 100));

        // A different key signs the same struct → recovery != configured subject.
        uint256 pkImposter = 0x10705702;
        bytes memory imposterSig = _sign(pkImposter, auth, action, subject);
        vm.expectRevert(abi.encodeWithSelector(ISubjectInitiatedModule.SubjectInitiatedInvalidSigner.selector, auth));
        module.submitSubjectInitiated(auth, CeremonyAxis.Reveal, action, imposterSig, 1, uint64(block.timestamp + 100));

        // Signature bound to a DIFFERENT action digest → recovery yields a different
        // address than `subject` for this action's typed data → rejected.
        bytes memory wrongActionSig = _sign(pkSubject, auth, keccak256("other-action"), subject);
        vm.expectRevert(abi.encodeWithSelector(ISubjectInitiatedModule.SubjectInitiatedInvalidSigner.selector, auth));
        module.submitSubjectInitiated(
            auth, CeremonyAxis.Reveal, action, wrongActionSig, 1, uint64(block.timestamp + 100)
        );

        // Wrong-chain signature (replay) → digest binds block.chainid, recovery fails.
        bytes32 wrongChainDomain = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid + 1, address(module)
            )
        );
        bytes32 wrongChainStruct = keccak256(abi.encode(_SUBJECT_ACTION_TYPEHASH, auth, action, subject));
        bytes32 wrongChainDigest = keccak256(abi.encodePacked(hex"1901", wrongChainDomain, wrongChainStruct));
        (uint8 wv, bytes32 wr, bytes32 ws) = vm.sign(pkSubject, wrongChainDigest);
        vm.expectRevert(abi.encodeWithSelector(ISubjectInitiatedModule.SubjectInitiatedInvalidSigner.selector, auth));
        module.submitSubjectInitiated(
            auth, CeremonyAxis.Reveal, action, abi.encodePacked(wr, ws, wv), 1, uint64(block.timestamp + 100)
        );

        // Sanity: a correctly bound subject signature is still accepted.
        module.submitSubjectInitiated(
            auth, CeremonyAxis.Reveal, action, _sign(pkSubject, auth, action, subject), 1, uint64(block.timestamp + 100)
        );
        assertTrue(module.evaluate(auth, action));
    }

    /// B3a: reconfiguring to rotate the subject signer must drop the prior signer's
    /// eligibility (epoch bump clears the prior subject from the active epoch).
    function test_B3a_reconfigureRotatesSubjectSigner() external {
        uint256 pkNew = 0x2E45AB;
        address newSubject = vm.addr(pkNew);

        // Reconfigure: rotate to a new subject signer.
        module.configureSubjectInitiated(auth, CeremonyAxis.Reveal, newSubject, configDigest);
        assertEq(module.subjectSigner(auth), newSubject);

        // The rotated-out subject can no longer submit, even with a valid prior-epoch signature.
        bytes memory oldSig = _sign(pkSubject, auth, action, subject);
        vm.expectRevert(abi.encodeWithSelector(ISubjectInitiatedModule.SubjectInitiatedInvalidSigner.selector, auth));
        module.submitSubjectInitiated(auth, CeremonyAxis.Reveal, action, oldSig, 1, uint64(block.timestamp + 100));

        // The new subject signs and is accepted under the new epoch.
        bytes memory newSig = _sign(pkNew, auth, action, newSubject);
        module.submitSubjectInitiated(auth, CeremonyAxis.Reveal, action, newSig, 1, uint64(block.timestamp + 100));
        assertTrue(module.evaluate(auth, action));
    }
}
