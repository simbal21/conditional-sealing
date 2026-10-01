import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";

/**
 * §3 — G4 binary-hash registry update (Phase 1 only).
 *
 * Triggers: reproducible-build release, Phase 1 daemon bugfix, sealed-code
 * runtime hardening, compiler/toolchain update, or suspected Phase 1
 * server compromise. Phase 1 is dev-scaffold only.
 *
 * Phase 1 entries write to G4AuthorityRegistry with `phase = 1` metadata.
 * Old binary remains historically valid (§3.5); clients use
 * `readEntryAt(G4AuthorityRegistry, ref, commit_block)` to verify
 * historical commits.
 */
export interface G4BinaryHashUpdateInput {
  readonly registryAddress: Address;
  readonly g4AuthorityRef: Hex;
  readonly binaryHash: Hex;
  readonly sourceCommitDigest: Hex;
  readonly buildEnvDigest: Hex;
  readonly testVectorDigest: Hex;
  readonly metadataHash: Hex;
  readonly effectiveBlock: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class G4BinaryHashUpdateCeremony extends RegistryAdditionCeremony {
  override readonly slug = "g4-binary-hash-update";
  override readonly specSection = "§3";
  override readonly catalogRowNumber = 1;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: G4BinaryHashUpdateInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "G4AuthorityRegistry",
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        phase: 1,
        g4AuthorityRef: input.g4AuthorityRef,
        binaryHash: input.binaryHash,
        sourceCommitDigest: input.sourceCommitDigest,
        buildEnvDigest: input.buildEnvDigest,
        testVectorDigest: input.testVectorDigest,
        metadataHash: input.metadataHash,
        effectiveBlock: input.effectiveBlock.toString(),
      },
      expectedEvents: ["EntryAdded"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
    });
  }
}
