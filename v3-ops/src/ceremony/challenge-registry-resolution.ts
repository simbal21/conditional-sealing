import type { Address, Hex } from "viem";
import { Ceremony, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";

/**
 * §12.7 — ChallengeRegistry pause/resolution. Halt-only.
 *
 * The PDA-scoped `CHALLENGE_RESOLVER_ROLE` is the only resolver authority and
 * cannot act outside its PDA scope. THREE resolver actions exactly:
 *   - `confirmNoIntervention` — sets `ConfirmedNoIntervention`, only allows
 *     gate signing through the normal `canGatesSign` path.
 *   - `haltCeremony` — sets `Halted`, MUST route through G4 refusal/artifact
 *     path; does NOT erase `RevealAuthorized`.
 *   - `extendChallenge` — for legal or G4 evidence collection; MUST respect
 *     extension caps and the 90-day pause/freeze ceiling for the registry
 *     surface lifetime (distinct from M2's per-challenge-event 72h max).
 *     MUST carry a `resolverActionRef` hash/CID.
 *
 * Resolver CANNOT alter reveal content, emit release, force G4 to sign,
 * delete state, or bypass refusal.
 *
 * FOUR events: `ChallengeOpened` (intake-side, not a resolver action),
 * `ChallengeResolved` (confirm/halt/dismiss), `ChallengeExtended`,
 * `ChallengeWithdrawn` (intake-side withdrawal).
 */
export type ChallengeResolverAction =
  | "confirmNoIntervention"
  | "haltCeremony"
  | "extendChallenge";

const VALID_ACTIONS: readonly ChallengeResolverAction[] = Object.freeze([
  "confirmNoIntervention",
  "haltCeremony",
  "extendChallenge",
]);

const MAX_EXTENSION_DAYS = 90;
const MAX_EXTENSION_SECONDS = MAX_EXTENSION_DAYS * 24 * 60 * 60;

export interface ChallengeResolutionInput {
  readonly challengeRegistryAddress: Address;
  readonly challengeId: Hex;
  readonly resolverAction: ChallengeResolverAction;
  /** Mandatory per §12.7 — resolver action artefact hash/CID. */
  readonly resolverActionRef: Hex;
  readonly hCommit: Hex;
  readonly pdaScope: Hex;
  /** extendChallenge only: extension duration in seconds (cap MAX_EXTENSION_SECONDS). */
  readonly extensionSeconds: number | null;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class ChallengeResolutionCeremony extends Ceremony {
  override readonly slug = "challenge-registry-resolution";
  override readonly specSection = "§12.7";
  override readonly catalogRowNumber = 13;
  override readonly governancePath = GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION;
  private readonly input: ChallengeResolutionInput;

  constructor(input: ChallengeResolutionInput) {
    super();
    if (!VALID_ACTIONS.includes(input.resolverAction)) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "proposal",
        {
          ceremonySlug: "challenge-registry-resolution",
          resolverAction: input.resolverAction,
        },
      );
    }
    if (
      !input.resolverActionRef ||
      input.resolverActionRef === "0x" + "00".repeat(32)
    ) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "proposal",
        {
          ceremonySlug: "challenge-registry-resolution",
          resolverAction: input.resolverAction,
        },
      );
    }
    if (input.resolverAction === "extendChallenge") {
      if (
        input.extensionSeconds === null ||
        input.extensionSeconds <= 0 ||
        input.extensionSeconds > MAX_EXTENSION_SECONDS
      ) {
        throw new CeremonyError(
          CeremonyErrorCode.TRIPWIRE_BYPASS,
          "proposal",
          {
            ceremonySlug: "challenge-registry-resolution",
            resolverAction: input.resolverAction,
          },
        );
      }
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
      challengeId: this.input.challengeId,
      resolverAction: this.input.resolverAction,
      resolverActionRef: this.input.resolverActionRef,
      hCommit: this.input.hCommit,
      pdaScope: this.input.pdaScope,
      extensionSeconds: this.input.extensionSeconds ?? 0,
    });
    return {
      proposalHash: hash,
      target: this.input.challengeRegistryAddress,
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
      message: "challenge_resolution_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        challengeId: this.input.challengeId,
        resolverAction: this.input.resolverAction,
        resolverActionRef: this.input.resolverActionRef,
        txHash,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const expected: CeremonyEventName =
      this.input.resolverAction === "extendChallenge" ? "ChallengeExtended" : "ChallengeResolved";
    if (args.context.dryRun) {
      this.recordEvent(expected);
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
    const required: CeremonyEventName =
      this.input.resolverAction === "extendChallenge" ? "ChallengeExtended" : "ChallengeResolved";
    if (!this.emittedEvents.includes(required)) {
      throw new CeremonyError(
        CeremonyErrorCode.REGISTRY_COLLISION,
        "verify",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
          resolverAction: this.input.resolverAction,
        },
      );
    }
    // halt-only invariant: even after a haltCeremony resolution, NO event
    // in the audit log may grant reveal.
    const releaseEvents: CeremonyEventName[] = ["RevealAuthorized"];
    for (const r of releaseEvents) {
      if (this.emittedEvents.includes(r)) {
        throw new CeremonyError(
          CeremonyErrorCode.TRIPWIRE_BYPASS,
          "verify",
          {
            ceremonyId: args.context.ceremonyId,
            ceremonySlug: this.slug,
            resolverAction: this.input.resolverAction,
          },
        );
      }
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "verify",
      message: "challenge_resolution_halt_only_verified",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        challengeId: this.input.challengeId,
        resolverAction: this.input.resolverAction,
      },
    });
  }
}

export const VALID_CHALLENGE_RESOLVER_ACTIONS = VALID_ACTIONS;
export const CHALLENGE_EXTENSION_MAX_DAYS = MAX_EXTENSION_DAYS;
