import type { Address, Hex } from "viem";
import { Ceremony, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import { PauseAuthority } from "../types/authority-enums.js";

/**
 * §12 — Pause deactivation (manual unpause; separate from §12.3 auto-lift).
 */
export interface PauseDeactivationInput {
  readonly conditionEngineAddress: Address;
  readonly pauseAuthorityMode: PauseAuthority;
  readonly pauseAuthorityId: Hex;
  readonly authorityProof: Hex;
  readonly hCommit: Hex;
  readonly unpauseReasonDigest: Hex;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class PauseDeactivationCeremony extends Ceremony {
  override readonly slug = "pause-deactivation";
  override readonly specSection = "§12";
  override readonly catalogRowNumber = 12;
  override readonly governancePath = GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION;
  private readonly input: PauseDeactivationInput;

  constructor(input: PauseDeactivationInput) {
    super();
    if (input.pauseAuthorityMode === PauseAuthority.NONE) {
      throw new CeremonyError(
        CeremonyErrorCode.QUORUM_MISSING,
        "proposal",
        { ceremonySlug: "pause-deactivation", pauseAuthorityMode: input.pauseAuthorityMode },
      );
    }
    this.input = input;
  }

  async proposal(_args: CeremonyRunArgs): Promise<{
    proposalHash: Hex;
    target: Address;
    data: Hex;
    salt: Hex;
  }> {
    const hash = proposalHash({
      ceremony: this.slug,
      hCommit: this.input.hCommit,
      pauseAuthorityMode: this.input.pauseAuthorityMode,
      unpauseReasonDigest: this.input.unpauseReasonDigest,
    });
    return {
      proposalHash: hash,
      target: this.input.conditionEngineAddress,
      data: this.input.addEntryCalldata,
      salt: this.input.salt,
    };
  }

  async queue(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const { txHash } = await args.chain.scheduleTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      salt: p.salt,
      delaySeconds: 0n,
    });
    this.recordTx(txHash);
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "queue",
      message: "unpause_proposal_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        hCommit: this.input.hCommit,
        pauseAuthorityMode: this.input.pauseAuthorityMode,
        txHash,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    if (args.context.dryRun) {
      this.recordEvent("PauseDeactivated");
      return;
    }
    const { txHash, events } = await args.chain.executeTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      salt: p.salt,
    });
    this.recordTx(txHash);
    for (const ev of events) this.recordEvent(ev.eventName);
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    if (!this.emittedEvents.includes("PauseDeactivated")) {
      throw new CeremonyError(
        CeremonyErrorCode.REGISTRY_COLLISION,
        "verify",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
        },
      );
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "verify",
      message: "unpause_visibility_verified",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
      },
    });
  }
}
