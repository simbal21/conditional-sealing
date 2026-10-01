// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";

import { AttestationGate } from "../../src/attestation/AttestationGate.sol";
import { ClaimDSL } from "../../src/dsl/ClaimDSL.sol";
import { IAttestationGate } from "../../src/engine/IConditionEngine.sol";
import { DSLVersionRegistry } from "../../src/registries/DSLVersionRegistry.sol";
import { OracleRegistry } from "../../src/registries/OracleRegistry.sol";
import { OracleSchemaRegistry } from "../../src/registries/OracleSchemaRegistry.sol";
import { DeprecationFlag } from "../../src/lib/Structs.sol";
import { Tags } from "../../src/lib/Tags.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract AttestationGateTest is Test {
    AttestationGate internal gate;
    ClaimDSL internal dsl;
    DSLVersionRegistry internal dslRegistry;
    OracleRegistry internal oracleRegistry;
    OracleSchemaRegistry internal schemaRegistry;

    uint256 internal oraclePk = 0xA11CE;
    address internal oracle;
    bytes32 internal oracleId;
    bytes32 internal schemaId = keccak256("schema");
    bytes32 internal dslRef = keccak256("dsl");
    bytes32 internal claimRef = keccak256("claim");
    bytes32 internal pathOk = keccak256("ok");
    bytes32 internal auth = keccak256("auth");
    bytes32 internal missingOracleId = keccak256("missing-oracle");
    bytes32 internal wrongSchemaId = keccak256("wrong-schema");
    address internal securityCouncil = address(0xB0B);
    address internal emergencyGovernance = address(0xCAFE);
    address internal pauser = address(0xDA7A);

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(100);
        oracle = vm.addr(oraclePk);
        oracleRegistry = OracleRegistry(
            ProxyDeploy.deployProxy(
                address(new OracleRegistry()),
                abi.encodeCall(OracleRegistry.initialize, (address(this), securityCouncil, emergencyGovernance, pauser))
            )
        );
        schemaRegistry = OracleSchemaRegistry(
            ProxyDeploy.deployProxy(
                address(new OracleSchemaRegistry()),
                abi.encodeCall(
                    OracleSchemaRegistry.initialize, (address(this), securityCouncil, emergencyGovernance, pauser)
                )
            )
        );
        dslRegistry = DSLVersionRegistry(
            ProxyDeploy.deployProxy(
                address(new DSLVersionRegistry()),
                abi.encodeCall(
                    DSLVersionRegistry.initialize, (address(this), securityCouncil, emergencyGovernance, pauser)
                )
            )
        );
        dsl = ClaimDSL(
            ProxyDeploy.deployProxy(
                address(new ClaimDSL()), abi.encodeCall(ClaimDSL.initialize, (address(this), address(dslRegistry)))
            )
        );
        gate = AttestationGate(
            ProxyDeploy.deployProxy(
                address(new AttestationGate()),
                abi.encodeCall(
                    AttestationGate.initialize,
                    (address(this), address(oracleRegistry), address(schemaRegistry), address(dslRegistry), address(dsl))
                )
            )
        );

        dslRegistry.addDSLVersion(dslRef, _dslEntry());
        _registerClaim();
        oracleId = oracleRegistry.computeOracleId(abi.encodePacked(oracle));
        oracleRegistry.addOracle(oracleId, _oracleEntry(schemaId));
        schemaRegistry.addSchema(schemaId, _schemaEntry());
        gate.setAuthorizationBlock(auth, uint64(block.number));
        gate.setClaimDSLVersion(claimRef, dslRef);
    }

    function test_verifyOracleAttestation_SucceedsAndRejectsSigmaShape() external {
        bytes32 digest = keccak256("attestation");
        dsl.registerContextUint(digest, pathOk, 1);
        bytes memory sig = _sign(digest);
        assertTrue(gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, sig, claimRef));

        bytes memory sigma = new bytes(96);
        vm.expectRevert(IAttestationGate.AttestationSigmaBytesForbidden.selector);
        gate.verifyOracleAttestation(auth, oracleId, schemaId, keccak256("sigma"), sigma, claimRef);
    }

    function test_failClosedPaths() external {
        bytes32 digest = keccak256("bad");
        dsl.registerContextUint(digest, pathOk, 1);
        bytes memory sig = _sign(digest);

        vm.expectRevert(abi.encodeWithSelector(IAttestationGate.AttestationOracleUnknown.selector, missingOracleId));
        gate.verifyOracleAttestation(auth, missingOracleId, schemaId, digest, sig, claimRef);

        vm.expectRevert(
            abi.encodeWithSelector(IAttestationGate.AttestationSchemaMismatch.selector, oracleId, wrongSchemaId)
        );
        gate.verifyOracleAttestation(auth, oracleId, wrongSchemaId, digest, sig, claimRef);

        vm.expectRevert(abi.encodeWithSelector(IAttestationGate.AttestationSignatureInvalid.selector, oracleId, digest));
        gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, _sign(keccak256("other")), claimRef);

        gate.setAttestationObservedAt(digest, uint64(block.timestamp - 2 days));
        vm.expectRevert(abi.encodeWithSelector(IAttestationGate.AttestationStale.selector, digest));
        gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, sig, claimRef);

        bytes32 falseDigest = keccak256("false");
        dsl.registerContextUint(falseDigest, pathOk, 0);
        vm.expectRevert(abi.encodeWithSelector(IAttestationGate.AttestationClaimFalse.selector, claimRef));
        gate.verifyOracleAttestation(auth, oracleId, schemaId, falseDigest, _sign(falseDigest), claimRef);
    }

    function test_schemaHistoricalLookup_CommitBlockSurvivesLaterTombstone() external {
        bytes32 digest = keccak256("rotated");
        dsl.registerContextUint(digest, pathOk, 1);
        bytes memory sig = _sign(digest);
        uint64 commitBlock = uint64(block.number);

        uint64 tombstoneBlock = commitBlock + 10;
        vm.roll(tombstoneBlock);
        schemaRegistry.tombstoneEntry(schemaId, tombstoneBlock);

        gate.setAuthorizationBlock(auth, commitBlock);
        assertTrue(gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, sig, claimRef));

        bytes32 newerDigest = keccak256("after-tombstone");
        dsl.registerContextUint(newerDigest, pathOk, 1);
        gate.setAuthorizationBlock(auth, tombstoneBlock);
        vm.expectRevert(abi.encodeWithSelector(IAttestationGate.AttestationSchemaMismatch.selector, oracleId, schemaId));
        gate.verifyOracleAttestation(auth, oracleId, schemaId, newerDigest, _sign(newerDigest), claimRef);
    }

    /// F-02: a signature over the RAW attestationDigest (the pre-fix construction, with no
    /// chainId/domain binding) must now be rejected; only a signature over the chain-bound
    /// preimage is accepted. Proves the recover-over-raw-digest vuln is closed.
    function test_F_02_rawDigestSignatureRejected() external {
        bytes32 digest = keccak256("f02-raw");
        dsl.registerContextUint(digest, pathOk, 1);

        // Old construction: oracle signs the raw digest. Was accepted pre-fix; now invalid.
        bytes memory rawSig = _signRaw(digest);
        vm.expectRevert(abi.encodeWithSelector(IAttestationGate.AttestationSignatureInvalid.selector, oracleId, digest));
        gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, rawSig, claimRef);

        // New construction: oracle signs the chain-bound preimage. Accepted.
        bytes memory boundSig = _sign(digest);
        assertTrue(gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, boundSig, claimRef));
    }

    /// F-02: a signature minted under a DIFFERENT chainId (the cross-chain replay attack —
    /// oracle reuses its secp256k1 key across Base Sepolia + Base Mainnet) is rejected on this
    /// chain. The same digest signed under THIS chainId is accepted, proving the binding works.
    function test_F_02_crossChainReplayRejected() external {
        bytes32 digest = keccak256("f02-xchain");
        dsl.registerContextUint(digest, pathOk, 1);

        uint256 thisChain = block.chainid;
        uint256 otherChain = thisChain == 8453 ? 84_532 : 8453; // Base Mainnet <-> Base Sepolia

        // Signature valid on `otherChain` is presented here (replay). Must be rejected.
        bytes memory foreignSig = _signForChain(digest, otherChain);
        vm.expectRevert(abi.encodeWithSelector(IAttestationGate.AttestationSignatureInvalid.selector, oracleId, digest));
        gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, foreignSig, claimRef);

        // Same digest signed for THIS chain is accepted.
        bytes memory localSig = _signForChain(digest, thisChain);
        assertTrue(gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, localSig, claimRef));
    }

    /// BR-F: the gate burns an attestationDigest on first successful verification; a second
    /// verification of the SAME digest (defense-in-depth replay, independent of any module-level
    /// consumed-set) reverts AttestationDigestConsumed.
    function test_BR_F_gateLevelSingleUse() external {
        bytes32 digest = keccak256("brf-once");
        dsl.registerContextUint(digest, pathOk, 1);
        bytes memory sig = _sign(digest);

        assertFalse(gate.attestationDigestConsumed(digest));
        assertTrue(gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, sig, claimRef));
        assertTrue(gate.attestationDigestConsumed(digest));

        // Replay of the same digest+signature is now blocked at the gate itself.
        vm.expectRevert(abi.encodeWithSelector(AttestationGate.AttestationDigestConsumed.selector, digest));
        gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, sig, claimRef);
    }

    /// BR-F: a FAILED verification must not consume the digest — a legitimate retry of a
    /// not-yet-accepted digest after a transient failure (e.g. claim not yet true) must succeed.
    function test_BR_F_failedVerifyDoesNotConsume() external {
        bytes32 digest = keccak256("brf-retry");
        dsl.registerContextUint(digest, pathOk, 0); // claim false -> verify reverts

        bytes memory sig = _sign(digest);
        vm.expectRevert(abi.encodeWithSelector(IAttestationGate.AttestationClaimFalse.selector, claimRef));
        gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, sig, claimRef);
        assertFalse(gate.attestationDigestConsumed(digest));

        // Condition now holds; the same digest is accepted (was NOT burned by the failure).
        dsl.registerContextUint(digest, pathOk, 1);
        assertTrue(gate.verifyOracleAttestation(auth, oracleId, schemaId, digest, sig, claimRef));
    }

    function _registerClaim() private {
        dsl.setCaps(
            bytes32(0),
            ClaimDSL.Caps({ maxNodes: 8, maxDepth: 4, maxInSetSize: 4, maxPathDepth: 2, maxEvaluationGas: 0 })
        );
        ClaimDSL.ClaimNode[] memory nodes = new ClaimDSL.ClaimNode[](2);
        nodes[0] = ClaimDSL.ClaimNode({ op: dsl.OP_PATH_ACCESS(), left: 0, right: 0, valueRef: pathOk, aux: 1 });
        nodes[1] = ClaimDSL.ClaimNode({ op: dsl.OP_EQ(), left: 0, right: 0, valueRef: bytes32(uint256(1)), aux: 0 });
        dsl.registerClaim(claimRef, nodes, 1);
    }

    // F-02: oracles now sign over the chain-bound preimage, not the raw digest. All
    // happy-path helpers route through this so the suite reflects the post-fix wire
    // construction; raw-digest signing is exercised explicitly in the F-02 test.
    // Computes the chain-bound preimage LOCALLY (must NOT call gate.chainBoundSigningDigest:
    // when _sign(...) is used as an inline argument right after vm.expectRevert(...), an external
    // staticcall inside the helper would latch expectRevert onto that view call instead of the
    // intended verifyOracleAttestation call). Mirrors _signForChain bound to block.chainid.
    function _sign(bytes32 digest) private view returns (bytes memory) {
        return _signForChain(digest, block.chainid);
    }

    // Signs over the raw attestationDigest (the pre-fix construction) so the F-02 test
    // can prove that an oracle signature without chain binding is now rejected.
    function _signRaw(bytes32 digest) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oraclePk, digest);
        return abi.encodePacked(r, s, v);
    }

    // Signs the chain-bound preimage as if it were produced under a DIFFERENT chainId,
    // for the cross-chain replay proof.
    function _signForChain(bytes32 digest, uint256 chainIdToBind) private view returns (bytes memory) {
        bytes32 signingDigest = keccak256(
            abi.encodePacked(Tags.TAG_ATTESTATION_CONTEXT_V3, chainIdToBind, auth, schemaId, digest)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oraclePk, signingDigest);
        return abi.encodePacked(r, s, v);
    }

    function _oracleEntry(bytes32 entrySchemaId) private view returns (OracleRegistry.OracleEntry memory) {
        return OracleRegistry.OracleEntry({
            oraclePubkeyOrAddress: abi.encodePacked(oracle),
            oracleType: 1,
            schemaId: entrySchemaId,
            canonicalExamplesHash: keccak256("examples"),
            trustTier: 2,
            metadataHash: keccak256("metadata"),
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: _zeroFlag(),
            isCanonical: true
        });
    }

    function _schemaEntry() private view returns (OracleSchemaRegistry.OracleSchemaEntry memory) {
        return OracleSchemaRegistry.OracleSchemaEntry({
            schemaHash: keccak256("schema-body"),
            validExamplesHash: keccak256("valid"),
            invalidExamplesHash: keccak256("invalid"),
            schemaVersion: 1,
            metadataHash: keccak256("metadata"),
            supportedOracleTypesMask: 0x02,
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: _zeroFlag(),
            isCanonical: true
        });
    }

    function _dslEntry() private view returns (DSLVersionRegistry.DSLVersionEntry memory) {
        return DSLVersionRegistry.DSLVersionEntry({
            interpreter: address(dsl),
            capSetHash: bytes32(0),
            customPredicateEnabled: false,
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
