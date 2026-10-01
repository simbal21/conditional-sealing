import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";

/**
 * §7A — QTSP signing root rotation.
 *
 * Adds a new QTSPRegistry entry under 7-day timelock and tombstones the
 * old entry. Historical QES-bound σ_subject signatures verify against
 * QTSPRegistry state at `commit_block`; a later root rotation cannot
 * retroactively degrade a commit that was QES-valid at signing time
 * (§7A.3).
 */
export interface QtspRootRotationInput {
  readonly registryAddress: Address;
  readonly oldEntryRef: Hex;
  readonly qtspProviderRef: Hex;
  readonly qtspRootPubkeyHash: Hex;
  readonly trustListEvidenceHash: Hex;
  readonly eIdasStatusUrlHash: Hex;
  readonly metadataHash: Hex;
  readonly counselReviewDigest: Hex;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlockForOld: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class QtspRootRotationCeremony extends RegistryAdditionCeremony {
  override readonly slug = "qtsp-root-rotation";
  override readonly specSection = "§7A";
  override readonly catalogRowNumber = 6;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: QtspRootRotationInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "QTSPRegistry",
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        oldEntryRef: input.oldEntryRef,
        qtspProviderRef: input.qtspProviderRef,
        qtspRootPubkeyHash: input.qtspRootPubkeyHash,
        trustListEvidenceHash: input.trustListEvidenceHash,
        eIdasStatusUrlHash: input.eIdasStatusUrlHash,
        metadataHash: input.metadataHash,
        counselReviewDigest: input.counselReviewDigest,
        effectiveBlock: input.effectiveBlock.toString(),
        tombstoneBlockForOld: input.tombstoneBlockForOld.toString(),
      },
      expectedEvents: ["EntryAdded", "EntryTombstoned"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
    });
  }
}
