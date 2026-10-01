// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IAttestationGate, IConditionModule, IOracleAttestationModule } from "../../src/engine/IConditionEngine.sol";
import { OracleAttestationModule } from "../../src/modules/OracleAttestationModule.sol";
import { ModuleTestBase } from "./PaymentObligationModule.t.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract MockAttestationGate is IAttestationGate {
    bool public result = true;

    function setResult(bool result_) external {
        result = result_;
    }

    function verifyOracleAttestation(bytes32, bytes32, bytes32, bytes32, bytes calldata oracleSignature, bytes32)
        external
        view
        returns (bool)
    {
        if (oracleSignature.length == 96) revert AttestationSigmaBytesForbidden();
        return result;
    }
}

contract OracleAttestationModuleTest is ModuleTestBase {
    OracleAttestationModule internal module;
    MockAttestationGate internal gate;
    bytes32 internal oracleId = keccak256("oracle");
    bytes32 internal schemaId = keccak256("schema");
    bytes32 internal claimRef = keccak256("claim");
    bytes32 internal digest = keccak256("attestation");
    bytes32 internal wrongOracleId = keccak256("wrong-oracle");

    function setUp() public {
        vm.warp(1_000_000);
        gate = new MockAttestationGate();
        module = OracleAttestationModule(
            ProxyDeploy.deployProxy(
                address(new OracleAttestationModule()),
                abi.encodeCall(OracleAttestationModule.initialize, (timelock, engine, address(gate)))
            )
        );
        module.configureOracleCondition(auth, oracleId, schemaId, claimRef, 0, configDigest);
    }

    function test_oracleAttestationAcceptsAndRejectsReplay() external {
        _assertNoAuthorizationEvents("src/modules/OracleAttestationModule.sol");
        module.submitOracleAttestation(auth, oracleId, schemaId, digest, bytes("sig"), "");
        assertTrue(module.evaluate(auth, digest));

        vm.expectRevert(
            abi.encodeWithSelector(IOracleAttestationModule.OracleAttestationDigestConsumed.selector, digest)
        );
        module.submitOracleAttestation(auth, oracleId, schemaId, digest, bytes("sig"), "");
    }

    function test_oracleRootMismatchAndClaimFalse() external {
        vm.expectRevert(
            abi.encodeWithSelector(IOracleAttestationModule.OracleAttestationRootMismatch.selector, auth, wrongOracleId)
        );
        module.submitOracleAttestation(auth, wrongOracleId, schemaId, digest, bytes("sig"), "");

        gate.setResult(false);
        vm.expectRevert(abi.encodeWithSelector(IConditionModule.ModuleConditionFalse.selector, auth));
        module.submitOracleAttestation(auth, oracleId, schemaId, keccak256("other"), bytes("sig"), "");
    }
}
