import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";

/**
 * §5 — Plugin-version update and signed distribution.
 *
 * Proposal binds the signed binary + manifest hash (§5.6). Activation
 * requires both registry effectiveness AND client-side verification of:
 * release signature, binary hash, manifest hash, PluginHashRegistry state
 * at `commit_block`. Rollback is NOT a mutable channel flip — it is
 * deprecate-current + activate-already-staged or queue-new-signed-binary.
 */
export interface PluginVersionUpdateInput {
  readonly registryAddress: Address;
  readonly pluginVersionDigest: Hex;
  readonly binaryHash: Hex;
  readonly sourceCommitDigest: Hex;
  readonly semverDigest: Hex;
  readonly buildEnvDigest: Hex;
  readonly lockfileDigest: Hex;
  readonly signedManifestHash: Hex;
  readonly testVectorDigest: Hex;
  readonly supportedProfileHash: Hex;
  readonly disabledProfileHash: Hex;
  readonly minCombinerSdkVersion: string;
  readonly supportedCommitVersionRange: string;
  readonly rolloutChannel: string;
  readonly effectiveBlock: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class PluginVersionUpdateCeremony extends RegistryAdditionCeremony {
  override readonly slug = "plugin-version-update";
  override readonly specSection = "§5";
  override readonly catalogRowNumber = 3;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: PluginVersionUpdateInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "PluginHashRegistry",
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        pluginVersionDigest: input.pluginVersionDigest,
        binaryHash: input.binaryHash,
        sourceCommitDigest: input.sourceCommitDigest,
        semverDigest: input.semverDigest,
        buildEnvDigest: input.buildEnvDigest,
        lockfileDigest: input.lockfileDigest,
        signedManifestHash: input.signedManifestHash,
        testVectorDigest: input.testVectorDigest,
        supportedProfileHash: input.supportedProfileHash,
        disabledProfileHash: input.disabledProfileHash,
        minCombinerSdkVersion: input.minCombinerSdkVersion,
        supportedCommitVersionRange: input.supportedCommitVersionRange,
        rolloutChannel: input.rolloutChannel,
        effectiveBlock: input.effectiveBlock.toString(),
      },
      expectedEvents: ["EntryAdded"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
    });
  }
}
