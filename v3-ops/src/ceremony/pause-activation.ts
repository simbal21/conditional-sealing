import type { Address, Hex } from "viem";
import { Ceremony, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import { PauseAuthority } from "../types/authority-enums.js";

const MAX_PAUSE_SECONDS = 90 * 24 * 60 * 60;

/**
 * §12 — Pause activation (Partner / Joint / None per §12.2).
 *
 * Pause is reversible and bounded. It blocks selected state advancement or
 * new authorization emissions. It NEVER deletes ciphertext, destroys keys,
 * grants release, alters reveal content, or resets historical state.
 *
 * §12.3 auto-lift: pause duration MUST be ≤ 90 days. Extension is a new
 * pause action subject to the same cap.
 *
 * §12.4 visibility: emits pause event with pauseAuthorityMode + reason
 * digest + start block + expiry block. Reason text off-chain or
 * digest/encrypted; no sensitive refusal text emitted.
 *
 * §12.6: pause CANNOT erase `RevealAuthorized`, alter delivery content, or
 * force G4 to sign. Cannot grant reveal.
 */
export interface PauseActivationInput {
  readonly conditionEngineAddress: Address;
  readonly pauseAuthorityMode: PauseAuthority;
  readonly pauseAuthorityId: Hex;
  readonly authorityProof: Hex;
  readonly hCommit: Hex;
  readonly reasonDigest: Hex;
  readonly durationSeconds: number;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class PauseActivationCeremony extends Ceremony {
  override readonly slug = "pause-activation";
  override readonly specSection = "§12";
  override readonly catalogRowNumber = 12;
  override readonly governancePath = GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION;
  private readonly input: PauseActivationInput;

  constructor(input: PauseActivationInput) {
    super();
    this.input = input;
    if (input.pauseAuthorityMode === PauseAuthority.NONE) {
      throw new CeremonyError(
        CeremonyErrorCode.QUORUM_MISSING,
        "proposal",
        {
          ceremonySlug: this.slug,
          pauseAuthorityMode: input.pauseAuthorityMode,
        },
      );
    }
    if (input.durationSeconds <= 0 || input.durationSeconds > MAX_PAUSE_SECONDS) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "proposal",
        {
          ceremonySlug: this.slug,
          pauseAuthorityMode: input.pauseAuthorityMode,
        },
      );
    }
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
      reasonDigest: this.input.reasonDigest,
      durationSeconds: this.input.durationSeconds,
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
      message: "pause_proposal_queued",
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
    const startTimestamp = await args.chain.readBlockTimestamp();
    const expiryTimestamp = startTimestamp + BigInt(this.input.durationSeconds);
    if (args.context.dryRun) {
      this.recordEvent("PauseActivated");
      await this.logger!.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "execute",
        message: "pause_dry_run_simulated",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
          pauseAuthorityMode: this.input.pauseAuthorityMode,
          dryRun: true,
        },
      });
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
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "execute",
      message: "pause_activated",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        pauseAuthorityMode: this.input.pauseAuthorityMode,
        startBlock: startTimestamp,
        expiryBlock: expiryTimestamp,
        txHash,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const expected: CeremonyEventName = "PauseActivated";
    if (!this.emittedEvents.includes(expected)) {
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
      message: "pause_visibility_verified",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        pauseAuthorityMode: this.input.pauseAuthorityMode,
      },
    });
  }
}
