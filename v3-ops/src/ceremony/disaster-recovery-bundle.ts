import type { Address, Hex } from "viem";
import { Ceremony, delayForPath, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";

/**
 * §14 — Disaster recovery bundle.
 *
 * §14.6 case matrix dispatch by `affectedSurface`:
 *   - "g4-phase2-authority-or-measurement" → DeprecationFlag + circuit
 *     breaker + 7-day replacement (unless standby exists).
 *   - "plugin-rotation" → DeprecationFlag on PluginHashRegistry + activate
 *     staged binary OR queue new signed distribution.
 *   - "oracle-compromise" → DeprecationFlag on oracle/schema entry + pause
 *     pending flows + replacement via §6.
 *
 * §14.7 cross-domain independence disclosure (public-copy-sensitive): in
 * Governance Phase 1, disaster-recovery statements MUST state that multisig
 * seats are Cealis-held; Phase 2 independence begins only after external
 * advisor seats are active.
 *
 * Testnet-only at M7 per brief lines 22 + 51.
 */
export type DisasterAffectedSurface =
  | "g4-phase2-authority-or-measurement"
  | "plugin-rotation"
  | "oracle-compromise";

export interface DisasterRecoveryInput {
  readonly registryAddress: Address;
  readonly affectedSurface: DisasterAffectedSurface;
  readonly affectedEntryRef: Hex;
  readonly canonicalInUse: boolean;
  readonly reasonCode: number;
  readonly disclosureCid: string;
  readonly disclosureCommitHash: Hex;
  readonly replacementStaged: boolean;
  /** Optional pre-staged replacement entry ref (skip 7-day delay if present). */
  readonly stagedReplacementRef: Hex | null;
  readonly metadataHash: Hex;
  readonly deprecationCalldata: Hex;
  readonly replacementCalldata: Hex;
  readonly salt: Hex;
}

export class DisasterRecoveryCeremony extends Ceremony {
  override readonly slug = "disaster-recovery-bundle";
  override readonly specSection = "§14";
  override readonly catalogRowNumber = 15;
  override readonly governancePath: GovernancePath;
  private readonly input: DisasterRecoveryInput;

  constructor(input: DisasterRecoveryInput) {
    super();
    this.input = input;
    // Canonical-in-use → 24h expedited; non-canonical → instant.
    this.governancePath = input.canonicalInUse
      ? GovernancePath.EXPEDITED_24H_DEPRECATION
      : GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION;
  }

  async proposal(args: CeremonyRunArgs): Promise<{
    proposalHash: Hex;
    target: Address;
    data: Hex;
    salt: Hex;
  }> {
    if (!this.input.disclosureCid || !this.input.disclosureCommitHash) {
      throw new CeremonyError(
        CeremonyErrorCode.DEPRECATION_DISCLOSURE_MISSING,
        "proposal",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          entryId: this.input.affectedEntryRef,
        },
      );
    }
    const hash = proposalHash({
      ceremony: this.slug,
      affectedSurface: this.input.affectedSurface,
      affectedEntryRef: this.input.affectedEntryRef,
      reasonCode: this.input.reasonCode,
      disclosureCid: this.input.disclosureCid,
      disclosureCommitHash: this.input.disclosureCommitHash,
    });
    return {
      proposalHash: hash,
      target: this.input.registryAddress,
      data: this.input.deprecationCalldata,
      salt: this.input.salt,
    };
  }

  async queue(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const delay = delayForPath(this.governancePath);
    const { txHash } = await args.chain.scheduleTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      salt: p.salt,
      delaySeconds: delay,
    });
    this.recordTx(txHash);
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "queue",
      message: "disaster_recovery_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        entryId: this.input.affectedEntryRef,
        reasonCode: this.input.reasonCode,
        disclosureCid: this.input.disclosureCid,
        disclosureCommitHash: this.input.disclosureCommitHash,
        governancePath: this.governancePath,
        txHash,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const expectedEvents: CeremonyEventName[] = ["DeprecationFlagSet", "DisclosurePublished"];
    if (this.input.replacementStaged) {
      expectedEvents.push("EntryAdded");
    }

    if (args.context.dryRun) {
      for (const ev of expectedEvents) this.recordEvent(ev);
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

    // Replacement path — separate execute call against staged calldata.
    if (this.input.replacementStaged) {
      const { txHash: rTx, events: rEvs } = await args.chain.executeTimelock({
        target: p.target,
        value: 0n,
        data: this.input.replacementCalldata,
        predecessor: ("0x" + "00".repeat(32)) as Hex,
        salt: p.salt,
      });
      this.recordTx(rTx);
      for (const ev of rEvs) this.recordEvent(ev.eventName);
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "execute",
      message: "disaster_recovery_executed",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        affectedSurface: this.input.affectedSurface,
        replacementStaged: this.input.replacementStaged,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const required: CeremonyEventName[] = ["DeprecationFlagSet", "DisclosurePublished"];
    for (const ev of required) {
      if (!this.emittedEvents.includes(ev)) {
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
    }
    // halt-only invariant — disaster recovery does NOT grant reveal.
    if (this.emittedEvents.includes("RevealAuthorized")) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "verify",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
        },
      );
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "verify",
      message: "disaster_recovery_halt_only_verified",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        affectedSurface: this.input.affectedSurface,
      },
    });
  }
}

const _ALL_SURFACES_FOR_TYPECHECK: readonly DisasterAffectedSurface[] = [
  "g4-phase2-authority-or-measurement",
  "plugin-rotation",
  "oracle-compromise",
];
void _ALL_SURFACES_FOR_TYPECHECK;
