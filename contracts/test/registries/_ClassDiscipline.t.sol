// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { Tags } from "../../src/lib/Tags.sol";
import { RegistryEntryAlreadyExists, RegistryLookupKeyMismatch } from "../../src/registries/PluginHashRegistry.sol";
import { PluginHashRegistry } from "../../src/registries/PluginHashRegistry.sol";
import { G4AuthorityRegistry } from "../../src/registries/G4AuthorityRegistry.sol";
import { DSLVersionRegistry } from "../../src/registries/DSLVersionRegistry.sol";
import { OracleRegistry } from "../../src/registries/OracleRegistry.sol";
import { QTSPRegistry } from "../../src/registries/QTSPRegistry.sol";

import { RegistryTestBase } from "./_HistoricalLookup.t.sol";

contract ClassDisciplineTest is RegistryTestBase {
    function setUp() public {
        _setRegistryBaseUp();
    }

    function test_pluginHash_UsesHelperTagPrefixedDigest() external {
        PluginHashRegistry registry = _deployPlugin();
        PluginHashRegistry.PluginEntry memory entry = _pluginEntry(false);
        bytes32 expected = helper.computePluginVersionDigest(entry.canonicalBinaryHash);

        assertEq(expected, helper.computePluginVersionDigest(entry.canonicalBinaryHash), "helper digest");
        vm.prank(timelock);
        registry.addPlugin(expected, entry);
        assertEq(registry.getPluginAt(expected, uint64(block.number)).canonicalBinaryHash, entry.canonicalBinaryHash);

        bytes32 wrong = keccak256(abi.encodePacked(entry.canonicalBinaryHash));
        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(RegistryLookupKeyMismatch.selector, expected, wrong));
        registry.addPlugin(wrong, entry);
    }

    function test_g4Authority_UsesHelperTagPrefixedRef() external {
        G4AuthorityRegistry registry = _deployG4();
        G4AuthorityRegistry.G4AuthorityEntry memory entry = _g4Entry(false);
        bytes32 expected = helper.computeG4AuthorityRef(entry.authorityPubkey);

        vm.prank(timelock);
        registry.addG4Authority(expected, entry);
        assertEq(registry.getG4AuthorityAt(expected, uint64(block.number)).authorityPubkey, entry.authorityPubkey);

        bytes32 wrong = keccak256(entry.authorityPubkey);
        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(RegistryLookupKeyMismatch.selector, expected, wrong));
        registry.addG4Authority(wrong, entry);
    }

    function test_oracle_UsesTagPrefixedOracleId() external {
        OracleRegistry registry = _deployOracle();
        OracleRegistry.OracleEntry memory entry = _oracleEntry(false);
        bytes32 expected = keccak256(abi.encodePacked(Tags.TAG_ORACLE_REGISTRY_V3, entry.oraclePubkeyOrAddress));
        assertEq(registry.computeOracleId(entry.oraclePubkeyOrAddress), expected, "oracle id");

        vm.prank(timelock);
        registry.addOracle(expected, entry);
        assertEq(registry.getOracleAt(expected, uint64(block.number)).schemaId, entry.schemaId);

        bytes32 wrong = keccak256(entry.oraclePubkeyOrAddress);
        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(RegistryLookupKeyMismatch.selector, expected, wrong));
        registry.addOracle(wrong, entry);
    }

    function test_dslVersion_ConsumesRawRefAsIs_AndDuplicateRawRefReverts() external {
        DSLVersionRegistry registry = _deployDSL();
        bytes32 rawRef = keccak256("raw-dsl-catalog-ref");

        vm.prank(timelock);
        registry.addDSLVersion(rawRef, _dslEntry(false));
        assertEq(registry.getDSLVersionAt(rawRef, uint64(block.number)).interpreter, address(0xD51));

        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(RegistryEntryAlreadyExists.selector, rawRef));
        registry.addDSLVersion(rawRef, _dslEntry(false));

        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryUnknown.selector, keccak256("other-ref")));
        registry.getDSLVersionAt(keccak256("other-ref"), uint64(block.number));
    }

    function test_qtsp_ConsumesRawRefAsIs_AndDuplicateRawRefReverts() external {
        QTSPRegistry registry = _deployQTSP();
        bytes32 rawRef = keccak256("raw-qtsp-catalog-ref");

        vm.prank(timelock);
        registry.addQTSP(rawRef, _qtspEntry(false));
        assertEq(registry.getQTSPAt(rawRef, uint64(block.number)).qtspRootPubkeyHash, keccak256("qtsp-root"));

        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(RegistryEntryAlreadyExists.selector, rawRef));
        registry.addQTSP(rawRef, _qtspEntry(false));

        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryUnknown.selector, keccak256("other-ref")));
        registry.getQTSPAt(keccak256("other-ref"), uint64(block.number));
    }
}
