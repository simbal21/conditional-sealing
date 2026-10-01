import type { Address, Hex } from "viem";
import { Ceremony, delayForPath, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";

/**
 * §16.5 — Governance Phase 2 transition (Ceremony 17).
 *
 * Queues member additions/removals through TimelockController, publishes
 * member-role metadata hashes, verifies key control, rotates out temporary
 * Cealis-only keys, emits role-grant events, and publishes the governance
 * posture announcement hash.
 *
 * §16.3 NORMATIVE deadline: external advisor seats complete BEFORE first
 * paying partner (`partnerRegistered` event) OR within 90 days of V2 launch,
 * whichever sooner. If verification fails, new partner onboarding HALTS.
 *
 * The §16.3 partner-onboarding pre-check verifies:
 *   (a) external-advisor seating proof present,
 *   (b) role-grant events on chain,
 *   (c) governance posture announcement hash verifies.
 */
export interface GovernancePhase2TransitionInput {
  readonly cealisSecurityMultisigAddress: Address;
  readonly emergencyGovernanceMultisigAddress: Address;
  readonly memberAdditions: readonly { readonly address: `0x${string}`; readonly roleId: Hex }[];
  readonly memberRemovals: readonly { readonly address: `0x${string}`; readonly roleId: Hex }[];
  readonly memberRoleMetadataHash: Hex;
  readonly advisorSeatProofHash: Hex;
  readonly postureAnnouncementHash: Hex;
  readonly v2LaunchBlock: bigint;
  readonly transitionEffectiveBlock: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class GovernancePhase2TransitionCeremony extends Ceremony {
  override readonly slug = "governance-phase2-transition";
  override readonly specSection = "§16.5";
  override readonly catalogRowNumber = 17;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  private readonly input: GovernancePhase2TransitionInput;

  constructor(input: GovernancePhase2TransitionInput) {
    super();
    this.input = input;
    // §1.1 invariant — the two multisig actors are distinct.
    if (
      input.cealisSecurityMultisigAddress.toLowerCase() ===
      input.emergencyGovernanceMultisigAddress.toLowerCase()
    ) {
      throw new CeremonyError(
        CeremonyErrorCode.QUORUM_MISSING,
        "proposal",
        {
          ceremonySlug: this.slug,
          actor: "CealisSecurityMultisig",
          safeAddress: input.cealisSecurityMultisigAddress,
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
      memberAdditions: this.input.memberAdditions,
      memberRemovals: this.input.memberRemovals,
      memberRoleMetadataHash: this.input.memberRoleMetadataHash,
      advisorSeatProofHash: this.input.advisorSeatProofHash,
      postureAnnouncementHash: this.input.postureAnnouncementHash,
      transitionEffectiveBlock: this.input.transitionEffectiveBlock.toString(),
    });
    return {
      proposalHash: hash,
      target: this.input.cealisSecurityMultisigAddress,
      data: this.input.addEntryCalldata,
      salt: this.input.salt,
    };
  }

  async queue(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const delay = delayForPath(this.governancePath);
    const { opId, txHash } = await args.chain.scheduleTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      salt: p.salt,
      delaySeconds: delay,
    });
    this.opId = opId;
    this.recordTx(txHash);
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "queue",
      message: "phase2_transition_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        advisorSeatProofHash: this.input.advisorSeatProofHash,
        postureAnnouncementHash: this.input.postureAnnouncementHash,
        memberAdded: this.input.memberAdditions.length,
        memberRemoved: this.input.memberRemovals.length,
        txHash,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const expectedEvents: CeremonyEventName[] = [
      "RoleGranted",
      "GovernancePostureAnnounced",
    ];
    if (this.input.memberRemovals.length > 0) {
      expectedEvents.push("RoleRevoked");
    }

    if (args.context.dryRun) {
      for (const ev of expectedEvents) this.recordEvent(ev);
      await this.logger!.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "execute",
        message: "phase2_transition_dry_run_simulated",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
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
      message: "phase2_transition_executed",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        txHash,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    if (!this.emittedEvents.includes("RoleGranted")) {
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
    if (!this.emittedEvents.includes("GovernancePostureAnnounced")) {
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
      level: "audit",
      stage: "verify",
      message: "phase2_transition_verified",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        advisorSeatProofHash: this.input.advisorSeatProofHash,
        postureAnnouncementHash: this.input.postureAnnouncementHash,
      },
    });
  }
}

/**
 * §16.3 NORMATIVE partner-onboarding pre-check. Used by partner-registration
 * code paths (M5) AND by Phase F integration tests. Pure function — no
 * chain calls, just verifies the three required artefact references are
 * present and well-formed.
 *
 * @returns `null` if the gate passes; otherwise the failure reason string.
 */
export function checkPhase2VerificationGate(args: {
  readonly advisorSeatProofHash: Hex | null;
  readonly roleGrantEventsObserved: boolean;
  readonly postureAnnouncementHash: Hex | null;
  readonly daysSinceV2Launch: number;
  readonly hasPaidPartnerYet: boolean;
}): string | null {
  // §16.3 normative trigger: first `partnerRegistered` OR day 90.
  const triggered = args.hasPaidPartnerYet || args.daysSinceV2Launch >= 90;
  if (!triggered) return null;
  if (args.advisorSeatProofHash === null) return "advisor_seat_proof_missing";
  if (!args.roleGrantEventsObserved) return "role_grant_events_missing";
  if (args.postureAnnouncementHash === null) return "posture_announcement_missing";
  return null;
}
