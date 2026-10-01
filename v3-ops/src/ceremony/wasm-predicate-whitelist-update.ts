import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";

/**
 * §10 — WASM predicate whitelist update.
 *
 * Adds a new audited WASM predicate binary to the PDA+ whitelist. The
 * selected predicate binary hashes are bound in `wasm_predicate_hashes_root`
 * inside `pda_root`. Historical PDAs keep their bound hashes; a later
 * whitelist update does NOT rewrite existing roots (§10.3).
 */
export interface WasmPredicateWhitelistInput {
  readonly registryAddress: Address;
  readonly predicateBinaryHash: Hex;
  readonly sourceCommitDigest: Hex;
  readonly auditDigest: Hex;
  readonly simulationVectorHash: Hex;
  readonly gasBound: bigint;
  readonly timeBoundMs: number;
  readonly allowedInputSchemaRef: Hex;
  readonly metadataHash: Hex;
  readonly effectiveBlock: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class WasmPredicateWhitelistUpdateCeremony extends RegistryAdditionCeremony {
  override readonly slug = "wasm-predicate-whitelist-update";
  override readonly specSection = "§10";
  override readonly catalogRowNumber = 10;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: WasmPredicateWhitelistInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "DSLVersionRegistry", // WASM whitelist lives under DSLVersionRegistry per §10 + §10.4
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        predicateBinaryHash: input.predicateBinaryHash,
        sourceCommitDigest: input.sourceCommitDigest,
        auditDigest: input.auditDigest,
        simulationVectorHash: input.simulationVectorHash,
        gasBound: input.gasBound.toString(),
        timeBoundMs: input.timeBoundMs,
        allowedInputSchemaRef: input.allowedInputSchemaRef,
        metadataHash: input.metadataHash,
        effectiveBlock: input.effectiveBlock.toString(),
      },
      expectedEvents: ["EntryAdded"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
    });
  }
}
