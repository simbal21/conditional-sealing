import { describe, it } from "vitest";
import type { Address, Hex } from "viem";
import { runRegistryAdditionSuite } from "../_fixtures/registry-add-helper.js";
import {
  G4BinaryHashUpdateCeremony,
  G4AuthorityRotationCeremony,
  PluginVersionUpdateCeremony,
  OracleOnboardingCeremony,
  OracleRotationCeremony,
  QtspOnboardingCeremony,
  QtspRootRotationCeremony,
  DslVersionUpdateCeremony,
  WasmPredicateWhitelistUpdateCeremony,
} from "../../src/ceremony/index.js";

const ADDR: Address = "0x1234567890123456789012345678901234567890";
const ADDR2: Address = "0x9876543210987654321098765432109876543210";
const H = (b: number) => (("0x" + b.toString(16).padStart(2, "0").repeat(32)) as Hex);

/**
 * Phase B end-to-end suite: every registry-addition ceremony walks the
 * standard 4-test scenario (dry-run, live, missing-event, deprecation-flag).
 * Per-ceremony unique logic (DCAP gate for §4) lives in dedicated files.
 */
describe("Phase B suite — 9 registry ceremonies", () => {
  it("g4-binary-hash-update (§3)", async () => {
    await runRegistryAdditionSuite({
      registryName: "G4AuthorityRegistry",
      expectedEvents: ["EntryAdded"],
      factory: () =>
        new G4BinaryHashUpdateCeremony({
          registryAddress: ADDR,
          g4AuthorityRef: H(0x01),
          binaryHash: H(0xaa),
          sourceCommitDigest: H(0xbb),
          buildEnvDigest: H(0xcc),
          testVectorDigest: H(0xdd),
          metadataHash: H(0xee),
          effectiveBlock: 2_000_000n,
          addEntryCalldata: H(0xff),
          salt: H(0x11),
        }),
    });
  });

  it("g4-authority-rotation Phase 1 (§4)", async () => {
    await runRegistryAdditionSuite({
      registryName: "G4AuthorityRegistry",
      expectedEvents: ["EntryAdded", "EntryTombstoned"],
      factory: () =>
        new G4AuthorityRotationCeremony({
          registryAddress: ADDR,
          phase: 1,
          g4AuthorityRef: H(0x02),
          authorityPubkey: H(0x03),
          teeMeasurement: null,
          dcapVerifierRef: null,
          dcapAcceptancePacket: null,
          metadataHash: H(0x04),
          effectiveBlock: 2_000_000n,
          tombstoneBlockForOld: 2_000_000n,
          oldEntryRef: H(0x05),
          addEntryCalldata: H(0x06),
          salt: H(0x07),
        }),
    });
  });

  it("plugin-version-update (§5)", async () => {
    await runRegistryAdditionSuite({
      registryName: "PluginHashRegistry",
      expectedEvents: ["EntryAdded"],
      factory: () =>
        new PluginVersionUpdateCeremony({
          registryAddress: ADDR,
          pluginVersionDigest: H(0x10),
          binaryHash: H(0x11),
          sourceCommitDigest: H(0x12),
          semverDigest: H(0x13),
          buildEnvDigest: H(0x14),
          lockfileDigest: H(0x15),
          signedManifestHash: H(0x16),
          testVectorDigest: H(0x17),
          supportedProfileHash: H(0x18),
          disabledProfileHash: H(0x19),
          minCombinerSdkVersion: "1.0.0",
          supportedCommitVersionRange: ">=0x0301",
          rolloutChannel: "stable",
          effectiveBlock: 2_000_000n,
          addEntryCalldata: H(0x1a),
          salt: H(0x1b),
        }),
    });
  });

  it("oracle-onboarding (§6)", async () => {
    await runRegistryAdditionSuite({
      registryName: "OracleRegistry",
      expectedEvents: ["OracleAdded", "OracleSchemaAdded"],
      factory: () =>
        new OracleOnboardingCeremony({
          registryAddress: ADDR,
          schemaRegistryAddress: ADDR2,
          oracleId: H(0x20),
          oracleTypeHash: H(0x21),
          operatorPubkeyHash: H(0x22),
          schemaHash: H(0x23),
          validExamplesHash: H(0x24),
          invalidExamplesHash: H(0x25),
          metadataHash: H(0x26),
          operatorContactHash: H(0x27),
          trustTier: 2,
          uptimeReputationHash: H(0x28),
          vettingDigest: H(0x29),
          submitterRoleScope: H(0x2a),
          effectiveBlock: 2_000_000n,
          addEntryCalldata: H(0x2b),
          salt: H(0x2c),
        }),
    });
  });

  it("oracle-rotation (§7)", async () => {
    await runRegistryAdditionSuite({
      registryName: "OracleRegistry",
      expectedEvents: ["OracleAdded", "EntryTombstoned"],
      factory: () =>
        new OracleRotationCeremony({
          registryAddress: ADDR,
          oldEntryRef: H(0x30),
          newOracleId: H(0x31),
          oracleTypeHash: H(0x32),
          operatorPubkeyHash: H(0x33),
          schemaHash: H(0x34),
          validExamplesHash: H(0x35),
          invalidExamplesHash: H(0x36),
          metadataHash: H(0x37),
          trustTier: 3,
          vettingDigest: H(0x38),
          effectiveBlock: 2_000_000n,
          tombstoneBlockForOld: 2_000_000n,
          addEntryCalldata: H(0x39),
          salt: H(0x3a),
        }),
    });
  });

  it("qtsp-onboarding (§7A)", async () => {
    await runRegistryAdditionSuite({
      registryName: "QTSPRegistry",
      expectedEvents: ["EntryAdded"],
      factory: () =>
        new QtspOnboardingCeremony({
          registryAddress: ADDR,
          qtspProviderRef: H(0x40),
          qtspProviderNameDigest: H(0x41),
          qtspJurisdictionRef: H(0x42),
          qtspRootPubkeyHash: H(0x43),
          eIdasStatusUrlHash: H(0x44),
          trustListEvidenceHash: H(0x45),
          supportedQesBundleProfile: "QC-PERSON-v1",
          metadataHash: H(0x46),
          counselReviewDigest: H(0x47),
          effectiveBlock: 2_000_000n,
          addEntryCalldata: H(0x48),
          salt: H(0x49),
        }),
    });
  });

  it("qtsp-root-rotation (§7A)", async () => {
    await runRegistryAdditionSuite({
      registryName: "QTSPRegistry",
      expectedEvents: ["EntryAdded", "EntryTombstoned"],
      factory: () =>
        new QtspRootRotationCeremony({
          registryAddress: ADDR,
          oldEntryRef: H(0x50),
          qtspProviderRef: H(0x51),
          qtspRootPubkeyHash: H(0x52),
          trustListEvidenceHash: H(0x53),
          eIdasStatusUrlHash: H(0x54),
          metadataHash: H(0x55),
          counselReviewDigest: H(0x56),
          effectiveBlock: 2_000_000n,
          tombstoneBlockForOld: 2_000_000n,
          addEntryCalldata: H(0x57),
          salt: H(0x58),
        }),
    });
  });

  it("dsl-version-update (§9)", async () => {
    await runRegistryAdditionSuite({
      registryName: "DSLVersionRegistry",
      expectedEvents: ["EntryAdded", "DSLVersionUsed"],
      factory: () =>
        new DslVersionUpdateCeremony({
          registryAddress: ADDR,
          interpreterBytecodeHash: H(0x60),
          interpreterContractAddress: ADDR2,
          astVersion: "1.0",
          capSetHash: H(0x61),
          testVectorDigest: H(0x62),
          compatibilityStatementHash: H(0x63),
          metadataHash: H(0x64),
          effectiveBlock: 2_000_000n,
          addEntryCalldata: H(0x65),
          salt: H(0x66),
        }),
    });
  });

  it("wasm-predicate-whitelist-update (§10)", async () => {
    await runRegistryAdditionSuite({
      registryName: "DSLVersionRegistry",
      expectedEvents: ["EntryAdded"],
      factory: () =>
        new WasmPredicateWhitelistUpdateCeremony({
          registryAddress: ADDR,
          predicateBinaryHash: H(0x70),
          sourceCommitDigest: H(0x71),
          auditDigest: H(0x72),
          simulationVectorHash: H(0x73),
          gasBound: 1_000_000n,
          timeBoundMs: 5_000,
          allowedInputSchemaRef: H(0x74),
          metadataHash: H(0x75),
          effectiveBlock: 2_000_000n,
          addEntryCalldata: H(0x76),
          salt: H(0x77),
        }),
    });
  });
});
