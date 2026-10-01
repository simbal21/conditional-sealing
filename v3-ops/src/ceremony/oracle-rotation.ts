import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";

/**
 * §7 — Oracle rotation.
 *
 * Adds a new OracleRegistry entry under 7-day timelock AND tombstones the
 * old entry for future commits. Schema migration (if any) adds a new
 * OracleSchemaRegistry entry; existing PDAs retain old schema semantics
 * (§7.4).
 *
 * Compromise path: emergency DeprecationFlag goes through §13.6
 * asymmetric governance (24h canonical-in-use OR 0h non-canonical); the
 * replacement entry still uses standard 7-day activation unless a
 * pre-queued standby exists.
 */
export interface OracleRotationInput {
  readonly registryAddress: Address;
  readonly oldEntryRef: Hex;
  readonly newOracleId: Hex;
  readonly oracleTypeHash: Hex;
  readonly operatorPubkeyHash: Hex;
  readonly schemaHash: Hex;
  readonly validExamplesHash: Hex;
  readonly invalidExamplesHash: Hex;
  readonly metadataHash: Hex;
  readonly trustTier: number;
  readonly vettingDigest: Hex;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlockForOld: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class OracleRotationCeremony extends RegistryAdditionCeremony {
  override readonly slug = "oracle-rotation";
  override readonly specSection = "§7";
  override readonly catalogRowNumber = 5;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: OracleRotationInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "OracleRegistry",
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        oldEntryRef: input.oldEntryRef,
        newOracleId: input.newOracleId,
        oracleTypeHash: input.oracleTypeHash,
        operatorPubkeyHash: input.operatorPubkeyHash,
        schemaHash: input.schemaHash,
        validExamplesHash: input.validExamplesHash,
        invalidExamplesHash: input.invalidExamplesHash,
        metadataHash: input.metadataHash,
        trustTier: input.trustTier,
        vettingDigest: input.vettingDigest,
        effectiveBlock: input.effectiveBlock.toString(),
        tombstoneBlockForOld: input.tombstoneBlockForOld.toString(),
      },
      expectedEvents: ["OracleAdded", "EntryTombstoned"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
    });
  }
}
