import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";

/**
 * §9 — DSL version update (DSLVersionRegistry).
 *
 * Deploys a new DSL interpreter contract and registers it under 7-day
 * timelock. Activation writes the DSLVersionRegistry entry with bytecode
 * hash, contract address, AST version, cap-set hash, test vector digest,
 * and compatibility statement.
 *
 * Backward compatibility (§9.3): existing PDAs continue evaluating under
 * the DSL version bound in their `pda_root` and commit_AAD. A new
 * interpreter cannot reinterpret old Claim ASTs.
 */
export interface DslVersionUpdateInput {
  readonly registryAddress: Address;
  readonly interpreterBytecodeHash: Hex;
  readonly interpreterContractAddress: Address;
  readonly astVersion: string;
  readonly capSetHash: Hex;
  readonly testVectorDigest: Hex;
  readonly compatibilityStatementHash: Hex;
  readonly metadataHash: Hex;
  readonly effectiveBlock: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class DslVersionUpdateCeremony extends RegistryAdditionCeremony {
  override readonly slug = "dsl-version-update";
  override readonly specSection = "§9";
  override readonly catalogRowNumber = 8;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: DslVersionUpdateInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "DSLVersionRegistry",
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        interpreterBytecodeHash: input.interpreterBytecodeHash,
        interpreterContractAddress: input.interpreterContractAddress,
        astVersion: input.astVersion,
        capSetHash: input.capSetHash,
        testVectorDigest: input.testVectorDigest,
        compatibilityStatementHash: input.compatibilityStatementHash,
        metadataHash: input.metadataHash,
        effectiveBlock: input.effectiveBlock.toString(),
      },
      expectedEvents: ["EntryAdded", "DSLVersionUsed"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
    });
  }
}
