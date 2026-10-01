import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";

/**
 * §7A — QTSP onboarding.
 *
 * QTSPRegistry follows OracleRegistry-style 7-day governance plus
 * QTSP-specific counsel/commercial vetting. The proposal packet adds
 * provider legal name digest, jurisdiction, EU Trusted List evidence,
 * eIDAS status URL hash, QTSP root pubkey hash, supported QES bundle
 * profile, partner archetypes allowed, and counsel-review digest.
 *
 * QTSP deprecation maps to G4 refusal code `0x04 integrity_fail` (§7A.4
 * — S2-1/S2-2 do not define a dedicated QTSP refusal code at this layer).
 */
export interface QtspOnboardingInput {
  readonly registryAddress: Address;
  readonly qtspProviderRef: Hex;
  readonly qtspProviderNameDigest: Hex;
  readonly qtspJurisdictionRef: Hex;
  readonly qtspRootPubkeyHash: Hex;
  readonly eIdasStatusUrlHash: Hex;
  readonly trustListEvidenceHash: Hex;
  readonly supportedQesBundleProfile: string;
  readonly metadataHash: Hex;
  readonly counselReviewDigest: Hex;
  readonly effectiveBlock: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class QtspOnboardingCeremony extends RegistryAdditionCeremony {
  override readonly slug = "qtsp-onboarding";
  override readonly specSection = "§7A";
  override readonly catalogRowNumber = 6;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: QtspOnboardingInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "QTSPRegistry",
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        qtspProviderRef: input.qtspProviderRef,
        qtspProviderNameDigest: input.qtspProviderNameDigest,
        qtspJurisdictionRef: input.qtspJurisdictionRef,
        qtspRootPubkeyHash: input.qtspRootPubkeyHash,
        eIdasStatusUrlHash: input.eIdasStatusUrlHash,
        trustListEvidenceHash: input.trustListEvidenceHash,
        supportedQesBundleProfile: input.supportedQesBundleProfile,
        metadataHash: input.metadataHash,
        counselReviewDigest: input.counselReviewDigest,
        effectiveBlock: input.effectiveBlock.toString(),
      },
      expectedEvents: ["EntryAdded"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
    });
  }
}
