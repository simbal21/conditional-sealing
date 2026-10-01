import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";

/**
 * §6 — Oracle onboarding.
 *
 * Queues both OracleRegistry + OracleSchemaRegistry entries in the same
 * proposal. Submitter-role wiring (`ORACLE_SUBMITTER_ROLE`) is granted by
 * TimelockController or the OracleRegistry-governed role path AFTER the
 * oracle and schema entries are effective (§6.5).
 *
 * Trust-tier and example sets MUST be vetted off-chain BEFORE the 7-day
 * timelock queues — the vetting digest is in the proposal metadata.
 *
 * Launch oracles (§6.7): Chainlink Automation for time + SubjectInitiated
 * self-oracle. These are normal registry entries, not hardcoded paths.
 */
export interface OracleOnboardingInput {
  readonly registryAddress: Address;
  readonly schemaRegistryAddress: Address;
  readonly oracleId: Hex;
  readonly oracleTypeHash: Hex;
  readonly operatorPubkeyHash: Hex;
  readonly schemaHash: Hex;
  readonly validExamplesHash: Hex;
  readonly invalidExamplesHash: Hex;
  readonly metadataHash: Hex;
  readonly operatorContactHash: Hex;
  readonly trustTier: number;
  readonly uptimeReputationHash: Hex;
  readonly vettingDigest: Hex;
  readonly effectiveBlock: bigint;
  readonly submitterRoleScope: Hex | null;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class OracleOnboardingCeremony extends RegistryAdditionCeremony {
  override readonly slug = "oracle-onboarding";
  override readonly specSection = "§6";
  override readonly catalogRowNumber = 4;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: OracleOnboardingInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "OracleRegistry",
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        oracleId: input.oracleId,
        oracleTypeHash: input.oracleTypeHash,
        operatorPubkeyHash: input.operatorPubkeyHash,
        schemaHash: input.schemaHash,
        validExamplesHash: input.validExamplesHash,
        invalidExamplesHash: input.invalidExamplesHash,
        metadataHash: input.metadataHash,
        operatorContactHash: input.operatorContactHash,
        trustTier: input.trustTier,
        uptimeReputationHash: input.uptimeReputationHash,
        vettingDigest: input.vettingDigest,
        submitterRoleScope: input.submitterRoleScope ?? null,
        effectiveBlock: input.effectiveBlock.toString(),
      },
      expectedEvents: ["OracleAdded", "OracleSchemaAdded"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
    });
  }
}
