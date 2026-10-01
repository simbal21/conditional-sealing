// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";

import { DisclosureRegistry } from "../../src/disclosure/DisclosureRegistry.sol";
import { DisclosureRevocationRegistry } from "../../src/disclosure/DisclosureRevocationRegistry.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract MockPlonkVerifier {
    bool internal immutable _result;

    constructor(bool result_) {
        _result = result_;
    }

    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool) {
        proof;
        return _result && publicInputs.length == 14;
    }
}

contract DisclosureRegistryTest is Test {
    DisclosureRevocationRegistry internal revocations;
    DisclosureRegistry internal registry;

    address internal timelock = address(0x6001);
    address internal orchestrator = address(0x6002);
    address internal revocationAdmin = address(0x6003);
    address internal sdOperator = address(0x6004);
    address internal revoker = address(0x6005);

    bytes32 internal disclosureId = keccak256("disclosure");
    bytes32 internal auth = keccak256("auth");
    bytes32 internal verifierRef = keccak256("verifier");
    bytes32 internal plonkVerifierRef = keccak256("plonk-verifier");

    function setUp() public {
        revocations = DisclosureRevocationRegistry(
            ProxyDeploy.deployProxy(
                address(new DisclosureRevocationRegistry()),
                abi.encodeCall(DisclosureRevocationRegistry.initialize, (timelock))
            )
        );
        registry = DisclosureRegistry(
            ProxyDeploy.deployProxy(
                address(new DisclosureRegistry()),
                abi.encodeCall(DisclosureRegistry.initialize, (timelock, address(revocations)))
            )
        );

        vm.startPrank(timelock);
        revocations.grantRole(Roles.ORCHESTRATOR_ROLE, orchestrator);
        revocations.grantRole(Roles.REVOCATION_ADMIN_ROLE, revocationAdmin);
        registry.grantRole(Roles.SD_OPERATOR_ROLE, sdOperator);
        vm.stopPrank();

        vm.prank(sdOperator);
        registry.registerVerifier(verifierRef);
    }

    function test_revocationRegistryViewReturnsInitAddress() external view {
        assertEq(registry.revocationRegistry(), address(revocations));
    }

    function test_verifyAndCommitRevertsWhenRevocationRegistryPaused() external {
        _register(disclosureId);
        vm.prank(timelock);
        revocations.pause(bytes32(0), uint64(block.timestamp + 1 days), keccak256("pause"));

        vm.prank(sdOperator);
        vm.expectRevert(DisclosureRegistry.RevocationRegistryUnavailable.selector);
        registry.verifyAndCommitDisclosure(
            disclosureId, auth, bytes32(0), verifierRef, hex"01", hex"02", keccak256("p")
        );
    }

    function test_verifyAndCommitRevertsWhenDisclosureRevoked() external {
        _register(disclosureId);
        vm.prank(revocationAdmin);
        revocations.revokeDisclosure(disclosureId, 2, keccak256("evidence"));

        vm.prank(sdOperator);
        vm.expectRevert(DisclosureRegistry.RevocationRegistryUnavailable.selector);
        registry.verifyAndCommitDisclosure(
            disclosureId, auth, bytes32(0), verifierRef, hex"01", hex"02", keccak256("p")
        );
    }

    function test_disclosureRevokedDelegatesCorrectly() external {
        _register(disclosureId);
        assertFalse(registry.disclosureRevoked(disclosureId));
        vm.prank(revoker);
        revocations.revokeDisclosure(disclosureId, 4, keccak256("evidence"));
        assertTrue(registry.disclosureRevoked(disclosureId));
    }

    function test_verifyAndCommitStoresDigestWhenVerifierKnownAndNotRevoked() external {
        _register(disclosureId);
        bytes32 digest = keccak256("proof");
        vm.prank(sdOperator);
        bool ok =
            registry.verifyAndCommitDisclosure(disclosureId, auth, bytes32(0), verifierRef, hex"01", hex"02", digest);
        assertTrue(ok);
        assertEq(registry.disclosureDigest(disclosureId), digest);
    }

    function test_registerVerifierContractDispatchesToPlonkVerifier() external {
        _register(disclosureId);
        MockPlonkVerifier verifier = new MockPlonkVerifier(true);
        bytes32 digest = keccak256("plonk-proof");

        vm.prank(sdOperator);
        registry.registerVerifierContract(plonkVerifierRef, address(verifier));

        vm.prank(sdOperator);
        bool ok = registry.verifyAndCommitDisclosure(
            disclosureId,
            auth,
            bytes32(0),
            plonkVerifierRef,
            hex"01",
            abi.encode(_publicInputs()),
            digest
        );

        assertTrue(ok);
        assertEq(registry.disclosureDigest(disclosureId), digest);
    }

    function test_plonkVerifierFalseResultRevertsOnCommit() external {
        _register(disclosureId);
        MockPlonkVerifier verifier = new MockPlonkVerifier(false);

        vm.prank(sdOperator);
        registry.registerVerifierContract(plonkVerifierRef, address(verifier));

        vm.prank(sdOperator);
        vm.expectRevert(abi.encodeWithSelector(DisclosureRegistry.DisclosureProofInvalid.selector, disclosureId));
        registry.verifyAndCommitDisclosure(
            disclosureId,
            auth,
            bytes32(0),
            plonkVerifierRef,
            hex"01",
            abi.encode(_publicInputs()),
            keccak256("plonk-proof")
        );
    }

    function test_unknownVerifierReverts() external {
        _register(disclosureId);
        bytes32 unknownVerifier = keccak256("unknown");
        vm.prank(sdOperator);
        vm.expectRevert(abi.encodeWithSelector(DisclosureRegistry.DisclosureVerifierUnknown.selector, unknownVerifier));
        registry.verifyAndCommitDisclosure(
            disclosureId, auth, bytes32(0), unknownVerifier, hex"01", hex"02", keccak256("p")
        );
    }

    function test_uupsUpgradeByNonTimelockReverts() external {
        DisclosureRegistry implementation = new DisclosureRegistry();
        bytes memory init = abi.encodeCall(DisclosureRegistry.initialize, (timelock, address(revocations)));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), init);
        DisclosureRegistry proxied = DisclosureRegistry(address(proxy));
        DisclosureRegistry newImplementation = new DisclosureRegistry();

        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, Roles.UPGRADER_ROLE
            )
        );
        proxied.upgradeToAndCall(address(newImplementation), "");
    }

    function _register(bytes32 id) internal {
        vm.prank(orchestrator);
        revocations.registerDisclosure(id, auth, keccak256("claim"), verifierRef, 10, revoker);
    }

    function _publicInputs() internal pure returns (uint256[] memory inputs) {
        inputs = new uint256[](14);
        for (uint256 i = 0; i < inputs.length; ++i) {
            inputs[i] = i + 1;
        }
    }
}
