import type { Address, Hex } from "viem";
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
  type RegistryAdditionCeremony,
} from "../../ceremony/index.js";
import type { DcapAcceptancePacket } from "../../m3-imports.js";

/**
 * Per-slug factory: parse the JSON input into the ceremony class.
 *
 * Each factory delegates field validation to TypeScript's runtime type
 * checks (Object.entries) plus strict spec-name shape verification via
 * the ceremony's `proposal()` step. Invalid input produces a clear error
 * the CLI surfaces.
 */
type CeremonyFactory = (input: Record<string, unknown>) => RegistryAdditionCeremony;

function asHex(value: unknown, field: string): Hex {
  if (typeof value !== "string" || !value.startsWith("0x")) {
    throw new Error(`field ${field} must be a 0x-prefixed hex string`);
  }
  return value as Hex;
}

function asAddress(value: unknown, field: string): Address {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`field ${field} must be a 20-byte 0x address`);
  }
  return value as Address;
}

function asBigInt(value: unknown, field: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "string") return BigInt(value);
  if (typeof value === "number") return BigInt(value);
  throw new Error(`field ${field} must be a bigint, string, or number`);
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`field ${field} must be a string`);
  }
  return value;
}

function asNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`field ${field} must be a finite number`);
  }
  return value;
}

function asHexOrNull(value: unknown, field: string): Hex | null {
  if (value === null) return null;
  return asHex(value, field);
}

export const CEREMONY_FACTORIES: Readonly<Record<string, CeremonyFactory>> = Object.freeze({
  "g4-binary-hash-update": (i) =>
    new G4BinaryHashUpdateCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      g4AuthorityRef: asHex(i.g4AuthorityRef, "g4AuthorityRef"),
      binaryHash: asHex(i.binaryHash, "binaryHash"),
      sourceCommitDigest: asHex(i.sourceCommitDigest, "sourceCommitDigest"),
      buildEnvDigest: asHex(i.buildEnvDigest, "buildEnvDigest"),
      testVectorDigest: asHex(i.testVectorDigest, "testVectorDigest"),
      metadataHash: asHex(i.metadataHash, "metadataHash"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    }),
  "g4-authority-rotation": (i) => {
    const phase = asNumber(i.phase, "phase");
    if (phase !== 1 && phase !== 2) throw new Error("phase must be 1 or 2");
    const dcapRaw = i.dcapAcceptancePacket as Record<string, unknown> | null | undefined;
    const dcap: DcapAcceptancePacket | null = dcapRaw
      ? {
          g4AuthorityRef: asHex(dcapRaw.g4AuthorityRef, "dcap.g4AuthorityRef"),
          phase: 2,
          authorityPubkey: asHex(dcapRaw.authorityPubkey, "dcap.authorityPubkey"),
          teeMeasurement: asHex(dcapRaw.teeMeasurement, "dcap.teeMeasurement"),
          dcapVerifierRef: asHex(dcapRaw.dcapVerifierRef, "dcap.dcapVerifierRef"),
          effectiveBlock: asBigInt(dcapRaw.effectiveBlock, "dcap.effectiveBlock"),
          metadataHash: asHex(dcapRaw.metadataHash, "dcap.metadataHash"),
          admissionAuthoritativeMode: asString(
            dcapRaw.admissionAuthoritativeMode,
            "dcap.admissionAuthoritativeMode",
          ) as DcapAcceptancePacket["admissionAuthoritativeMode"],
          acceptedTcbStatuses: (dcapRaw.acceptedTcbStatuses as string[]) ?? [],
          vendorFamilyClassification: asString(
            dcapRaw.vendorFamilyClassification,
            "dcap.vendorFamilyClassification",
          ),
          litG4DisjointnessVerified:
            (dcapRaw.litG4DisjointnessVerified as boolean) ?? false,
          collateralFreshnessUnix: asNumber(
            dcapRaw.collateralFreshnessUnix,
            "dcap.collateralFreshnessUnix",
          ),
          quoteProofDigest: asHex(dcapRaw.quoteProofDigest, "dcap.quoteProofDigest"),
          userDataDigest: asHex(dcapRaw.userDataDigest, "dcap.userDataDigest"),
        }
      : null;
    return new G4AuthorityRotationCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      phase: phase as 1 | 2,
      g4AuthorityRef: asHex(i.g4AuthorityRef, "g4AuthorityRef"),
      authorityPubkey: asHex(i.authorityPubkey, "authorityPubkey"),
      teeMeasurement: asHexOrNull(i.teeMeasurement, "teeMeasurement"),
      dcapVerifierRef: asHexOrNull(i.dcapVerifierRef, "dcapVerifierRef"),
      dcapAcceptancePacket: dcap,
      metadataHash: asHex(i.metadataHash, "metadataHash"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      tombstoneBlockForOld: asBigInt(i.tombstoneBlockForOld, "tombstoneBlockForOld"),
      oldEntryRef: asHex(i.oldEntryRef, "oldEntryRef"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    });
  },
  "plugin-version-update": (i) =>
    new PluginVersionUpdateCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      pluginVersionDigest: asHex(i.pluginVersionDigest, "pluginVersionDigest"),
      binaryHash: asHex(i.binaryHash, "binaryHash"),
      sourceCommitDigest: asHex(i.sourceCommitDigest, "sourceCommitDigest"),
      semverDigest: asHex(i.semverDigest, "semverDigest"),
      buildEnvDigest: asHex(i.buildEnvDigest, "buildEnvDigest"),
      lockfileDigest: asHex(i.lockfileDigest, "lockfileDigest"),
      signedManifestHash: asHex(i.signedManifestHash, "signedManifestHash"),
      testVectorDigest: asHex(i.testVectorDigest, "testVectorDigest"),
      supportedProfileHash: asHex(i.supportedProfileHash, "supportedProfileHash"),
      disabledProfileHash: asHex(i.disabledProfileHash, "disabledProfileHash"),
      minCombinerSdkVersion: asString(i.minCombinerSdkVersion, "minCombinerSdkVersion"),
      supportedCommitVersionRange: asString(i.supportedCommitVersionRange, "supportedCommitVersionRange"),
      rolloutChannel: asString(i.rolloutChannel, "rolloutChannel"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    }),
  "oracle-onboarding": (i) =>
    new OracleOnboardingCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      schemaRegistryAddress: asAddress(i.schemaRegistryAddress, "schemaRegistryAddress"),
      oracleId: asHex(i.oracleId, "oracleId"),
      oracleTypeHash: asHex(i.oracleTypeHash, "oracleTypeHash"),
      operatorPubkeyHash: asHex(i.operatorPubkeyHash, "operatorPubkeyHash"),
      schemaHash: asHex(i.schemaHash, "schemaHash"),
      validExamplesHash: asHex(i.validExamplesHash, "validExamplesHash"),
      invalidExamplesHash: asHex(i.invalidExamplesHash, "invalidExamplesHash"),
      metadataHash: asHex(i.metadataHash, "metadataHash"),
      operatorContactHash: asHex(i.operatorContactHash, "operatorContactHash"),
      trustTier: asNumber(i.trustTier, "trustTier"),
      uptimeReputationHash: asHex(i.uptimeReputationHash, "uptimeReputationHash"),
      vettingDigest: asHex(i.vettingDigest, "vettingDigest"),
      submitterRoleScope: asHexOrNull(i.submitterRoleScope, "submitterRoleScope"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    }),
  "oracle-rotation": (i) =>
    new OracleRotationCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      oldEntryRef: asHex(i.oldEntryRef, "oldEntryRef"),
      newOracleId: asHex(i.newOracleId, "newOracleId"),
      oracleTypeHash: asHex(i.oracleTypeHash, "oracleTypeHash"),
      operatorPubkeyHash: asHex(i.operatorPubkeyHash, "operatorPubkeyHash"),
      schemaHash: asHex(i.schemaHash, "schemaHash"),
      validExamplesHash: asHex(i.validExamplesHash, "validExamplesHash"),
      invalidExamplesHash: asHex(i.invalidExamplesHash, "invalidExamplesHash"),
      metadataHash: asHex(i.metadataHash, "metadataHash"),
      trustTier: asNumber(i.trustTier, "trustTier"),
      vettingDigest: asHex(i.vettingDigest, "vettingDigest"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      tombstoneBlockForOld: asBigInt(i.tombstoneBlockForOld, "tombstoneBlockForOld"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    }),
  "qtsp-onboarding": (i) =>
    new QtspOnboardingCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      qtspProviderRef: asHex(i.qtspProviderRef, "qtspProviderRef"),
      qtspProviderNameDigest: asHex(i.qtspProviderNameDigest, "qtspProviderNameDigest"),
      qtspJurisdictionRef: asHex(i.qtspJurisdictionRef, "qtspJurisdictionRef"),
      qtspRootPubkeyHash: asHex(i.qtspRootPubkeyHash, "qtspRootPubkeyHash"),
      eIdasStatusUrlHash: asHex(i.eIdasStatusUrlHash, "eIdasStatusUrlHash"),
      trustListEvidenceHash: asHex(i.trustListEvidenceHash, "trustListEvidenceHash"),
      supportedQesBundleProfile: asString(i.supportedQesBundleProfile, "supportedQesBundleProfile"),
      metadataHash: asHex(i.metadataHash, "metadataHash"),
      counselReviewDigest: asHex(i.counselReviewDigest, "counselReviewDigest"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    }),
  "qtsp-root-rotation": (i) =>
    new QtspRootRotationCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      oldEntryRef: asHex(i.oldEntryRef, "oldEntryRef"),
      qtspProviderRef: asHex(i.qtspProviderRef, "qtspProviderRef"),
      qtspRootPubkeyHash: asHex(i.qtspRootPubkeyHash, "qtspRootPubkeyHash"),
      trustListEvidenceHash: asHex(i.trustListEvidenceHash, "trustListEvidenceHash"),
      eIdasStatusUrlHash: asHex(i.eIdasStatusUrlHash, "eIdasStatusUrlHash"),
      metadataHash: asHex(i.metadataHash, "metadataHash"),
      counselReviewDigest: asHex(i.counselReviewDigest, "counselReviewDigest"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      tombstoneBlockForOld: asBigInt(i.tombstoneBlockForOld, "tombstoneBlockForOld"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    }),
  "dsl-version-update": (i) =>
    new DslVersionUpdateCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      interpreterBytecodeHash: asHex(i.interpreterBytecodeHash, "interpreterBytecodeHash"),
      interpreterContractAddress: asAddress(i.interpreterContractAddress, "interpreterContractAddress"),
      astVersion: asString(i.astVersion, "astVersion"),
      capSetHash: asHex(i.capSetHash, "capSetHash"),
      testVectorDigest: asHex(i.testVectorDigest, "testVectorDigest"),
      compatibilityStatementHash: asHex(i.compatibilityStatementHash, "compatibilityStatementHash"),
      metadataHash: asHex(i.metadataHash, "metadataHash"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    }),
  "wasm-predicate-whitelist-update": (i) =>
    new WasmPredicateWhitelistUpdateCeremony({
      registryAddress: asAddress(i.registryAddress, "registryAddress"),
      predicateBinaryHash: asHex(i.predicateBinaryHash, "predicateBinaryHash"),
      sourceCommitDigest: asHex(i.sourceCommitDigest, "sourceCommitDigest"),
      auditDigest: asHex(i.auditDigest, "auditDigest"),
      simulationVectorHash: asHex(i.simulationVectorHash, "simulationVectorHash"),
      gasBound: asBigInt(i.gasBound, "gasBound"),
      timeBoundMs: asNumber(i.timeBoundMs, "timeBoundMs"),
      allowedInputSchemaRef: asHex(i.allowedInputSchemaRef, "allowedInputSchemaRef"),
      metadataHash: asHex(i.metadataHash, "metadataHash"),
      effectiveBlock: asBigInt(i.effectiveBlock, "effectiveBlock"),
      addEntryCalldata: asHex(i.addEntryCalldata, "addEntryCalldata"),
      salt: asHex(i.salt, "salt"),
    }),
});

export function hasParser(slug: string): boolean {
  return slug in CEREMONY_FACTORIES;
}
