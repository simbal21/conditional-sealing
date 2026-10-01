// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";

import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { IBaseRegistry } from "../../src/base/IBaseRegistry.sol";
import { CealisIdentifierHelpers } from "../../src/helpers/CealisIdentifierHelpers.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { DeprecationFlag } from "../../src/lib/Structs.sol";
import {
    GovernedRegistry,
    RegistryCanonicalRequiresTimelock,
    RegistryCanonicalDeprecationNotReady
} from "../../src/registries/PluginHashRegistry.sol";
import { PluginHashRegistry } from "../../src/registries/PluginHashRegistry.sol";
import { G4AuthorityRegistry } from "../../src/registries/G4AuthorityRegistry.sol";
import { DSLVersionRegistry } from "../../src/registries/DSLVersionRegistry.sol";
import { OracleRegistry } from "../../src/registries/OracleRegistry.sol";
import { QTSPRegistry } from "../../src/registries/QTSPRegistry.sol";
import { OracleSchemaRegistry } from "../../src/registries/OracleSchemaRegistry.sol";

interface IUpgradeToAndCall {
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
}

abstract contract RegistryTestBase is Test {
    address internal timelock = address(0xA11CE);
    address internal securityCouncil = address(0xB0B);
    address internal emergencyGovernance = address(0xCAFE);
    address internal pauser = address(0xDA7A);
    address internal g4Operator = address(0x4444);
    address internal stranger = address(0xBEEF);

    bytes32 internal constant CID = keccak256("disclosure.cid");
    bytes32 internal constant REASON = keccak256("pause.reason");
    bytes internal constant SUMMARY = bytes("disclosure summary");

    CealisIdentifierHelpers internal helper;

    function _setRegistryBaseUp() internal {
        helper = new CealisIdentifierHelpers();
        vm.warp(1_000_000);
        vm.roll(100);
    }

    function _deployPlugin() internal returns (PluginHashRegistry registry) {
        registry = PluginHashRegistry(
            _proxy(
                address(new PluginHashRegistry()),
                abi.encodeCall(
                    PluginHashRegistry.initialize,
                    (timelock, securityCouncil, emergencyGovernance, pauser, address(helper))
                )
            )
        );
    }

    function _deployG4() internal returns (G4AuthorityRegistry registry) {
        registry = G4AuthorityRegistry(
            _proxy(
                address(new G4AuthorityRegistry()),
                abi.encodeCall(
                    G4AuthorityRegistry.initialize,
                    (timelock, securityCouncil, emergencyGovernance, pauser, g4Operator, address(helper))
                )
            )
        );
    }

    function _deployDSL() internal returns (DSLVersionRegistry registry) {
        registry = DSLVersionRegistry(
            _proxy(
                address(new DSLVersionRegistry()),
                abi.encodeCall(DSLVersionRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser))
            )
        );
    }

    function _deployOracle() internal returns (OracleRegistry registry) {
        registry = OracleRegistry(
            _proxy(
                address(new OracleRegistry()),
                abi.encodeCall(OracleRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser))
            )
        );
    }

    function _deployQTSP() internal returns (QTSPRegistry registry) {
        registry = QTSPRegistry(
            _proxy(
                address(new QTSPRegistry()),
                abi.encodeCall(QTSPRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser))
            )
        );
    }

    function _deploySchema() internal returns (OracleSchemaRegistry registry) {
        registry = OracleSchemaRegistry(
            _proxy(
                address(new OracleSchemaRegistry()),
                abi.encodeCall(OracleSchemaRegistry.initialize, (timelock, securityCouncil, emergencyGovernance, pauser))
            )
        );
    }

    function _pluginEntry(bool canonical) internal view returns (PluginHashRegistry.PluginEntry memory) {
        return PluginHashRegistry.PluginEntry({
            canonicalBinaryHash: keccak256("plugin.bin"),
            sourceCommitDigest: keccak256("plugin.source"),
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: _zeroFlag(),
            isCanonical: canonical
        });
    }

    function _g4Entry(bool canonical) internal view returns (G4AuthorityRegistry.G4AuthorityEntry memory) {
        return G4AuthorityRegistry.G4AuthorityEntry({
            phase: 2,
            authorityPubkey: bytes("g4-authority-pubkey"),
            binaryHashOrMeasurement: keccak256("measurement"),
            dcapVerifierRef: keccak256("dcap"),
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: _zeroFlag(),
            isCanonical: canonical
        });
    }

    function _dslEntry(bool canonical) internal view returns (DSLVersionRegistry.DSLVersionEntry memory) {
        return DSLVersionRegistry.DSLVersionEntry({
            interpreter: address(0xD51),
            capSetHash: keccak256("caps"),
            customPredicateEnabled: false,
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: _zeroFlag(),
            isCanonical: canonical
        });
    }

    function _oracleEntry(bool canonical) internal view returns (OracleRegistry.OracleEntry memory) {
        return OracleRegistry.OracleEntry({
            oraclePubkeyOrAddress: bytes("oracle-pubkey"),
            oracleType: 1,
            schemaId: keccak256("schema"),
            canonicalExamplesHash: keccak256("examples"),
            trustTier: 2,
            metadataHash: keccak256("metadata"),
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: _zeroFlag(),
            isCanonical: canonical
        });
    }

    function _qtspEntry(bool canonical) internal view returns (QTSPRegistry.QTSPEntry memory) {
        return QTSPRegistry.QTSPEntry({
            qtspRootPubkeyHash: keccak256("qtsp-root"),
            jurisdiction: 0x4445,
            eidasStatusUrlHash: keccak256("eidas-url"),
            metadataHash: keccak256("metadata"),
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: _zeroFlag(),
            isCanonical: canonical
        });
    }

    function _schemaEntry(bool canonical) internal view returns (OracleSchemaRegistry.OracleSchemaEntry memory) {
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
            isCanonical: canonical
        });
    }

    function _zeroFlag() internal pure returns (DeprecationFlag memory) {
        return DeprecationFlag({
            deprecated: false,
            deprecationBlockTimestamp: 0,
            deprecationReasonCode: 0,
            disclosureCid: bytes32(0),
            disclosureCommitHash: bytes32(0),
            disclosureVerifiedBlock: 0,
            autoClearTimestamp: 0,
            isCanonicalAtSet: false
        });
    }

    function _assertRegistryPauseSurface(GovernedRegistry registry) internal {
        bytes32 scope = registry.GLOBAL_REGISTRY_SCOPE();
        uint64 sevenDays = uint64(block.timestamp) + 7 days;

        vm.prank(pauser);
        registry.pause(scope, sevenDays, REASON);
        (bool active, uint64 until, bytes32 reasonRef) = registry.isPaused(scope);
        assertTrue(active, "registry pause active");
        assertEq(until, sevenDays, "pause until");
        assertEq(reasonRef, REASON, "pause reason");

        vm.warp(sevenDays + 1);
        (active,,) = registry.isPaused(scope);
        assertFalse(active, "registry pause auto-expires");

        uint64 tooLong = uint64(block.timestamp) + 7 days + 1;
        vm.prank(pauser);
        vm.expectRevert();
        registry.pause(scope, tooLong, REASON);
    }

    function _assertNonCanonicalDeprecationLifecycle(GovernedRegistry registry, bytes32 id) internal {
        bytes32 summaryHash = keccak256(SUMMARY);
        vm.prank(securityCouncil);
        registry.deprecateEntry(id, 1, CID, summaryHash);

        DeprecationFlag memory flag = registry.deprecationFlag(id);
        assertTrue(flag.deprecated, "flag active");
        assertEq(flag.deprecationReasonCode, 1, "reason code");
        assertFalse(flag.isCanonicalAtSet, "noncanonical");

        vm.warp(flag.autoClearTimestamp);
        registry.triggerAutoClear(id);
        assertFalse(registry.deprecationFlag(id).deprecated, "auto-cleared");

        vm.prank(securityCouncil);
        vm.expectRevert(
            abi.encodeWithSelector(IBaseRegistry.RegistryCooldownActive.selector, id, uint64(block.timestamp + 30 days))
        );
        registry.deprecateEntry(id, 1, CID, summaryHash);

        vm.prank(timelock);
        registry.deprecateEntryByTimelock(id, 1, CID, summaryHash);
        assertTrue(registry.deprecationFlag(id).deprecated, "timelock can redeprecate during cooldown");
    }

    function _assertCanonicalDeprecationRequiresExpeditedTimelock(GovernedRegistry registry, bytes32 id) internal {
        bytes32 summaryHash = keccak256(SUMMARY);
        vm.prank(securityCouncil);
        vm.expectRevert(abi.encodeWithSelector(RegistryCanonicalRequiresTimelock.selector, id));
        registry.deprecateEntry(id, 1, CID, summaryHash);

        vm.prank(securityCouncil);
        registry.queueCanonicalDeprecation(id, 1, CID, summaryHash);

        uint64 readyAt = uint64(block.timestamp + 24 hours);
        vm.prank(timelock);
        vm.expectRevert(abi.encodeWithSelector(RegistryCanonicalDeprecationNotReady.selector, id, readyAt));
        registry.executeCanonicalDeprecation(id);

        vm.warp(readyAt);
        vm.prank(timelock);
        registry.executeCanonicalDeprecation(id);

        DeprecationFlag memory flag = registry.deprecationFlag(id);
        assertTrue(flag.deprecated, "canonical flag active");
        assertTrue(flag.isCanonicalAtSet, "canonical at set");
    }

    function _expectUnauthorizedUpgrade(address proxy, address newImplementation) internal {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, Roles.UPGRADER_ROLE
            )
        );
        IUpgradeToAndCall(proxy).upgradeToAndCall(newImplementation, "");
    }

    function _proxy(address implementation, bytes memory initializerData) internal returns (address) {
        return address(new ERC1967Proxy(implementation, initializerData));
    }
}

contract HistoricalLookupTest is RegistryTestBase {
    function setUp() public {
        _setRegistryBaseUp();
    }

    function test_historicalLookup_PluginHash() external {
        PluginHashRegistry registry = _deployPlugin();
        PluginHashRegistry.PluginEntry memory entry = _pluginEntry(false);
        bytes32 id = helper.computePluginVersionDigest(entry.canonicalBinaryHash);
        vm.prank(timelock);
        registry.addPlugin(id, entry);
        _assertHistoricalPlugin(registry, id, uint64(block.number));
    }

    function test_historicalLookup_G4Authority() external {
        G4AuthorityRegistry registry = _deployG4();
        G4AuthorityRegistry.G4AuthorityEntry memory entry = _g4Entry(false);
        bytes32 id = helper.computeG4AuthorityRef(entry.authorityPubkey);
        vm.prank(timelock);
        registry.addG4Authority(id, entry);
        _assertHistoricalG4(registry, id, uint64(block.number));
    }

    function test_historicalLookup_DSLVersion() external {
        DSLVersionRegistry registry = _deployDSL();
        bytes32 id = keccak256("raw-dsl-ref");
        vm.prank(timelock);
        registry.addDSLVersion(id, _dslEntry(false));
        _assertHistoricalDSL(registry, id, uint64(block.number));
    }

    function test_historicalLookup_Oracle() external {
        OracleRegistry registry = _deployOracle();
        OracleRegistry.OracleEntry memory entry = _oracleEntry(false);
        bytes32 id = registry.computeOracleId(entry.oraclePubkeyOrAddress);
        vm.prank(timelock);
        registry.addOracle(id, entry);
        _assertHistoricalOracle(registry, id, uint64(block.number));
    }

    function test_historicalLookup_QTSP() external {
        QTSPRegistry registry = _deployQTSP();
        bytes32 id = keccak256("raw-qtsp-ref");
        vm.prank(timelock);
        registry.addQTSP(id, _qtspEntry(false));
        _assertHistoricalQTSP(registry, id, uint64(block.number));
    }

    function test_historicalLookup_OracleSchema() external {
        OracleSchemaRegistry registry = _deploySchema();
        bytes32 id = keccak256("schema-id");
        vm.prank(timelock);
        registry.addSchema(id, _schemaEntry(false));
        _assertHistoricalSchema(registry, id, uint64(block.number));
    }

    function _tombstone(GovernedRegistry registry, bytes32 id, uint64 effectiveBlock) private returns (uint64) {
        vm.roll(effectiveBlock + 10);
        uint64 tombstoneBlock = effectiveBlock + 10;
        vm.prank(timelock);
        registry.tombstoneEntry(id, tombstoneBlock);
        return tombstoneBlock;
    }

    function _expectTombstoned(bytes32 id, uint64 blockNumber) private {
        vm.expectRevert(abi.encodeWithSelector(IBaseRegistry.RegistryEntryTombstoned.selector, id, blockNumber));
    }

    function _assertHistoricalPlugin(PluginHashRegistry registry, bytes32 id, uint64 n) private {
        assertEq(registry.getPluginAt(id, n).effectiveBlock, n, "effective at N");
        uint64 m = _tombstone(registry, id, n);
        assertEq(registry.getPluginAt(id, m - 1).effectiveBlock, n, "effective before tombstone");
        _expectTombstoned(id, m);
        registry.getPluginAt(id, m);
        assertEq(registry.getPluginAt(id, n).effectiveBlock, n, "N remains effective");
    }

    function _assertHistoricalG4(G4AuthorityRegistry registry, bytes32 id, uint64 n) private {
        assertEq(registry.getG4AuthorityAt(id, n).effectiveBlock, n, "effective at N");
        uint64 m = _tombstone(registry, id, n);
        assertEq(registry.getG4AuthorityAt(id, m - 1).effectiveBlock, n, "effective before tombstone");
        _expectTombstoned(id, m);
        registry.getG4AuthorityAt(id, m);
        assertEq(registry.getG4AuthorityAt(id, n).effectiveBlock, n, "N remains effective");
    }

    function _assertHistoricalDSL(DSLVersionRegistry registry, bytes32 id, uint64 n) private {
        assertEq(registry.getDSLVersionAt(id, n).effectiveBlock, n, "effective at N");
        uint64 m = _tombstone(registry, id, n);
        assertEq(registry.getDSLVersionAt(id, m - 1).effectiveBlock, n, "effective before tombstone");
        _expectTombstoned(id, m);
        registry.getDSLVersionAt(id, m);
        assertEq(registry.getDSLVersionAt(id, n).effectiveBlock, n, "N remains effective");
    }

    function _assertHistoricalOracle(OracleRegistry registry, bytes32 id, uint64 n) private {
        assertEq(registry.getOracleAt(id, n).effectiveBlock, n, "effective at N");
        uint64 m = _tombstone(registry, id, n);
        assertEq(registry.getOracleAt(id, m - 1).effectiveBlock, n, "effective before tombstone");
        _expectTombstoned(id, m);
        registry.getOracleAt(id, m);
        assertEq(registry.getOracleAt(id, n).effectiveBlock, n, "N remains effective");
    }

    function _assertHistoricalQTSP(QTSPRegistry registry, bytes32 id, uint64 n) private {
        assertEq(registry.getQTSPAt(id, n).effectiveBlock, n, "effective at N");
        uint64 m = _tombstone(registry, id, n);
        assertEq(registry.getQTSPAt(id, m - 1).effectiveBlock, n, "effective before tombstone");
        _expectTombstoned(id, m);
        registry.getQTSPAt(id, m);
        assertEq(registry.getQTSPAt(id, n).effectiveBlock, n, "N remains effective");
    }

    function _assertHistoricalSchema(OracleSchemaRegistry registry, bytes32 id, uint64 n) private {
        assertEq(registry.getSchemaAt(id, n).effectiveBlock, n, "effective at N");
        uint64 m = _tombstone(registry, id, n);
        assertEq(registry.getSchemaAt(id, m - 1).effectiveBlock, n, "effective before tombstone");
        _expectTombstoned(id, m);
        registry.getSchemaAt(id, m);
        assertEq(registry.getSchemaAt(id, n).effectiveBlock, n, "N remains effective");
    }
}
