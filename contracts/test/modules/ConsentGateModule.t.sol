// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IConsentGateModule } from "../../src/engine/IConditionEngine.sol";
import { ConsentGateModule } from "../../src/modules/ConsentGateModule.sol";
import { ModuleTestBase } from "./PaymentObligationModule.t.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract ConsentGateModuleTest is ModuleTestBase {
    ConsentGateModule internal module;
    bytes32 internal consentDigest = keccak256("consent");
    bytes32 internal badConsentDigest = keccak256("bad-consent");

    // SC-F-06: authorities must be real keypairs so the module can recover the EIP-712 signer.
    uint256 internal pkA = 0xA11CE;
    uint256 internal pkB = 0xB0B;
    address internal authorityA;
    address internal authorityB;

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisConsentGate");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    bytes32 private constant _CONSENT_TYPEHASH =
        keccak256("Consent(bytes32 authorizationId,bytes32 consentDigest,address authority)");

    function setUp() public {
        vm.warp(1_000_000);
        authorityA = vm.addr(pkA);
        authorityB = vm.addr(pkB);
        module = ConsentGateModule(
            ProxyDeploy.deployProxy(
                address(new ConsentGateModule()), abi.encodeCall(ConsentGateModule.initialize, (timelock, engine))
            )
        );
        address[] memory authorities = new address[](2);
        authorities[0] = authorityA;
        authorities[1] = authorityB;
        module.configureConsent(auth, consentDigest, authorities, 2, uint64(block.timestamp + 1 days), configDigest);
    }

    function _digest(bytes32 authorizationId, bytes32 cDigest, address authority) private view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid, address(module)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_CONSENT_TYPEHASH, authorizationId, cDigest, authority));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    function _sign(uint256 pk, bytes32 authorizationId, bytes32 cDigest, address authority)
        private
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _digest(authorizationId, cDigest, authority));
        return abi.encodePacked(r, s, v);
    }

    function test_consentThresholdExpiryAndEligibility() external {
        _assertNoAuthorizationEvents("src/modules/ConsentGateModule.sol");
        module.submitConsent(auth, authorityA, consentDigest, _sign(pkA, auth, consentDigest, authorityA), "");
        assertFalse(module.evaluate(auth, consentDigest));

        vm.expectRevert(
            abi.encodeWithSelector(IConsentGateModule.ConsentAuthorityIneligible.selector, auth, address(0xC))
        );
        module.submitConsent(auth, address(0xC), consentDigest, bytes("sig-c"), "");

        module.submitConsent(auth, authorityB, consentDigest, _sign(pkB, auth, consentDigest, authorityB), "");
        assertTrue(module.advance(auth, consentDigest, ""));
    }

    function test_consentDigestMismatchAndExpiry() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IConsentGateModule.ConsentDigestMismatch.selector, auth, consentDigest, badConsentDigest
            )
        );
        module.submitConsent(auth, authorityA, badConsentDigest, bytes("sig"), "");

        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(
            abi.encodeWithSelector(IConsentGateModule.ConsentExpired.selector, auth, uint64(1_000_000 + 1 days))
        );
        module.submitConsent(auth, authorityA, consentDigest, bytes("sig"), "");
    }

    /// SC-F-06: the trusted caller cannot forge consent by claiming an allow-listed authority
    /// with arbitrary non-empty envelope bytes. Recovery must equal the claimed authority.
    /// FAILS against pre-fix code (which only checked envelope length != 0), PASSES with fix.
    function test_SC_F_06_forgedConsentRejected() external {
        bytes memory junk = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));
        vm.expectRevert(
            abi.encodeWithSelector(IConsentGateModule.ConsentAuthorityIneligible.selector, auth, authorityA)
        );
        module.submitConsent(auth, authorityA, consentDigest, junk, "");

        // authorityB signs but caller claims it counts for authorityA → recovery mismatch.
        bytes memory bSig = _sign(pkB, auth, consentDigest, authorityA);
        vm.expectRevert(
            abi.encodeWithSelector(IConsentGateModule.ConsentAuthorityIneligible.selector, auth, authorityA)
        );
        module.submitConsent(auth, authorityA, consentDigest, bSig, "");

        // Cross-chain replay: digest binds block.chainid → recovery fails on this chain.
        bytes32 wrongChainDomain = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid + 1, address(module)
            )
        );
        bytes32 wrongChainStruct = keccak256(abi.encode(_CONSENT_TYPEHASH, auth, consentDigest, authorityA));
        bytes32 wrongChainDigest = keccak256(abi.encodePacked(hex"1901", wrongChainDomain, wrongChainStruct));
        (uint8 wv, bytes32 wr, bytes32 ws) = vm.sign(pkA, wrongChainDigest);
        vm.expectRevert(
            abi.encodeWithSelector(IConsentGateModule.ConsentAuthorityIneligible.selector, auth, authorityA)
        );
        module.submitConsent(auth, authorityA, consentDigest, abi.encodePacked(wr, ws, wv), "");

        // Sanity: a correctly bound signature is accepted and counted.
        module.submitConsent(auth, authorityA, consentDigest, _sign(pkA, auth, consentDigest, authorityA), "");
        assertEq(module.consentState(auth).count, 1);
    }

    /// B3a: reconfiguring to remove an authority must drop that authority's eligibility.
    /// FAILS against pre-fix code (eligibility flag never cleared → removed authority still counts),
    /// PASSES with fix (epoch bump clears prior eligibility + count).
    function test_B3a_reconfigureClearsRemovedAuthority() external {
        address authorityC = vm.addr(0xC0FFEE);

        // First config: A consents (count 1).
        module.submitConsent(auth, authorityA, consentDigest, _sign(pkA, auth, consentDigest, authorityA), "");
        assertEq(module.consentState(auth).count, 1);

        // Reconfigure: remove authorityA, keep authorityB, add authorityC. New threshold 1.
        address[] memory authorities = new address[](2);
        authorities[0] = authorityB;
        authorities[1] = authorityC;
        module.configureConsent(auth, consentDigest, authorities, 1, uint64(block.timestamp + 1 days), configDigest);

        // Old count must be wiped.
        assertEq(module.consentState(auth).count, 0);

        // The removed authority can no longer submit, even with a valid signature.
        vm.expectRevert(
            abi.encodeWithSelector(IConsentGateModule.ConsentAuthorityIneligible.selector, auth, authorityA)
        );
        module.submitConsent(auth, authorityA, consentDigest, _sign(pkA, auth, consentDigest, authorityA), "");

        // A retained authority still works under the new epoch.
        module.submitConsent(auth, authorityB, consentDigest, _sign(pkB, auth, consentDigest, authorityB), "");
        assertTrue(module.advance(auth, consentDigest, ""));
    }
}
