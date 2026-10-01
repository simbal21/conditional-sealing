import type { Address, Hex } from "viem";
import { Ceremony, type CeremonyRunArgs, delayForPath } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import {
  GovernancePath,
  type CeremonyEventName,
} from "../types/ceremony.js";

/**
 * Inputs every registry-addition ceremony provides. The seven §3..§10
 * scripts that follow this template differ only in:
 *   - which registry they target,
 *   - what fields go into the proposal payload,
 *   - which event names they expect on execute (EntryAdded vs OracleAdded etc.),
 *   - any extra invariants (Phase 2 DCAP gate for §4, manifest hash for §5).
 */
export interface RegistryAddProposalInput {
  /** Registry name (one of the 5 V3 + adjacent surfaces) */
  readonly registry: string;
  /** Contract address holding the registry */
  readonly contractAddress: Address;
  /** Calldata for the registry `addEntry` function */
  readonly addEntryCalldata: Hex;
  /** Salt for timelock op id derivation (deterministic) */
  readonly salt: Hex;
  /** Predecessor op id, or 0x0 for no predecessor */
  readonly predecessor: Hex;
  /** Canonical payload fields (used for proposal hash + audit log) */
  readonly payload: Record<string, unknown>;
  /** Event names expected at execute */
  readonly expectedEvents: readonly CeremonyEventName[];
  /** Effective block the new entry will be tagged with */
  readonly effectiveBlock: bigint;
  /** Governance path — defaults to TIMELOCK_7D_ADDITION */
  readonly governancePath?: GovernancePath;
  /** Optional pre-execution hook (e.g. §4.2.1 DCAP gate) */
  readonly preExecuteHook?: (args: CeremonyRunArgs) => Promise<void>;
}

export abstract class RegistryAdditionCeremony extends Ceremony {
  abstract readonly inputBuilder: (args: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;
  override readonly governancePath: GovernancePath = GovernancePath.TIMELOCK_7D_ADDITION;

  // Cached input from proposal() so execute()/verify() can read it.
  private cachedInput: RegistryAddProposalInput | null = null;

  async proposal(args: CeremonyRunArgs): Promise<{
    proposalHash: Hex;
    target: Address;
    data: Hex;
    salt: Hex;
  }> {
    const input = await this.inputBuilder(args);
    this.cachedInput = input;
    const hash = proposalHash({
      ceremony: this.slug,
      registry: input.registry,
      effectiveBlock: input.effectiveBlock.toString(),
      payload: input.payload,
    });
    return {
      proposalHash: hash,
      target: input.contractAddress,
      data: input.addEntryCalldata,
      salt: input.salt,
    };
  }

  async queue(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const input = this.requireInput();
    const path = input.governancePath ?? this.governancePath;
    const delay = delayForPath(path);
    const { opId, txHash } = await args.chain.scheduleTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: input.predecessor,
      salt: p.salt,
      delaySeconds: delay,
    });
    this.opId = opId;
    this.recordTx(txHash);
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "queue",
      message: "timelock_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        registryName: input.registry,
        txHash,
        governancePath: path,
        effectiveBlock: input.effectiveBlock,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const input = this.requireInput();
    // Pre-execute hook — §4.2.1 DCAP gate or similar.
    if (input.preExecuteHook !== undefined) {
      await input.preExecuteHook(args);
    }
    // In dry-run, simulate the execute by pre-loading expected events into
    // the chain client so the verify step has something to assert on.
    if (args.context.dryRun) {
      await this.logger!.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "execute",
        message: "execute_dry_run_simulated",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
          dryRun: true,
        },
      });
      for (const ev of input.expectedEvents) this.recordEvent(ev);
      return;
    }
    const { txHash, events } = await args.chain.executeTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: input.predecessor,
      salt: p.salt,
    });
    this.recordTx(txHash);
    for (const ev of events) {
      this.recordEvent(ev.eventName);
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "execute",
      message: "timelock_executed",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        txHash,
        registryName: input.registry,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const input = this.requireInput();
    // 1. Every expected event must have been observed (or simulated in dry-run).
    for (const ev of input.expectedEvents) {
      if (!this.emittedEvents.includes(ev)) {
        throw new CeremonyError(
          CeremonyErrorCode.REGISTRY_COLLISION,
          "verify",
          {
            ceremonyId: args.context.ceremonyId,
            registryName: input.registry,
            proposalHash: p.proposalHash,
          },
        );
      }
    }
    // 2. The new entry must NOT carry a deprecation flag at execute time.
    if (!args.context.dryRun) {
      const flag = await args.chain.readDeprecationFlag({
        registry: input.registry,
        entryRef: p.proposalHash,
      });
      if (flag !== null && flag.flagSet) {
        throw new CeremonyError(
          CeremonyErrorCode.REGISTRY_COLLISION,
          "verify",
          {
            ceremonyId: args.context.ceremonyId,
            registryName: input.registry,
            proposalHash: p.proposalHash,
            reasonCode: flag.reasonCode,
          },
        );
      }
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "verify",
      message: "post_execute_verified",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        registryName: input.registry,
      },
    });
  }

  private requireInput(): RegistryAddProposalInput {
    if (this.cachedInput === null) {
      throw new CeremonyError(
        CeremonyErrorCode.REGISTRY_COLLISION,
        "queue",
        { ceremonySlug: this.slug },
      );
    }
    return this.cachedInput;
  }
}
