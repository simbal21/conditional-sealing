import type { Address, Hex } from "viem";
import { Ceremony, delayForPath, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import { PdaPlusSubClass } from "../m4-imports.js";

/**
 * §10A — PDA+ governance sub-class ceremonies.
 *
 * 5 sub-classes per §10A.1 table:
 *   1. TimelockController-7d additions (REGISTRY_ADMIN_ROLE)
 *   2. CealisSecurityMultisig deprecations (SECURITY_COUNCIL_ROLE,
 *      0h non-canonical / 24h canonical-in-use)
 *   3. CealisSecurityMultisig with circuit breaker
 *      (SECURITY_COUNCIL_ROLE + EMERGENCY_GOVERNANCE_ROLE)
 *   4. PDA+ conditional-rule constraint adjustment (7-day)
 *   5. PDA+ conditional-rule addition (codepath-bound, 7-day after
 *      evidence lock; requires UPGRADER_ROLE if code changes)
 *
 * Halt-only invariant (§10A.4): emergency circuit breaker cannot grant
 * reveal, change recipients, alter pda_root, delete ciphertext, or bypass
 * post_challenge_reveal_in_progress.
 */
export interface PdaPlusGovernanceUpdateInput {
  readonly subClass: PdaPlusSubClass;
  readonly registryAddress: Address;
  readonly addedContentRef: Hex;
  readonly affectedArchetypes: readonly string[];
  readonly templateId: Hex;
  readonly defaultRowHash: Hex;
  readonly diffHash: Hex;
  readonly auditDigest: Hex;
  readonly testDigest: Hex;
  readonly simulationVectorHash: Hex;
  readonly inspectionRenderingHash: Hex;
  readonly authorLockReviewHash: Hex;
  readonly metadataHash: Hex;
  readonly effectiveBlock: bigint;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
  /** Sub-class 2/3 only: disclosure metadata. */
  readonly disclosureCid?: string | null;
  readonly disclosureCommitHash?: Hex | null;
  /** Sub-class 3 only: bounded emergency duration. */
  readonly emergencyDurationSeconds?: number | null;
  readonly emergencyScopeHash?: Hex | null;
}

export class PdaPlusGovernanceUpdateCeremony extends Ceremony {
  override readonly slug = "pda-plus-governance-update";
  override readonly specSection = "§10A";
  override readonly catalogRowNumber = 9;
  override readonly governancePath: GovernancePath;
  private readonly input: PdaPlusGovernanceUpdateInput;

  constructor(input: PdaPlusGovernanceUpdateInput) {
    super();
    this.input = input;
    this.governancePath = governancePathForSubClass(input.subClass);
    if (input.subClass === PdaPlusSubClass.DEPRECATION_MULTISIG) {
      if (!input.disclosureCid || !input.disclosureCommitHash) {
        throw new CeremonyError(
          CeremonyErrorCode.DEPRECATION_DISCLOSURE_MISSING,
          "proposal",
          { ceremonySlug: this.slug, subClassNumber: input.subClass },
        );
      }
    }
    if (input.subClass === PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER) {
      if (!input.emergencyDurationSeconds || !input.emergencyScopeHash) {
        throw new CeremonyError(
          CeremonyErrorCode.TRIPWIRE_BYPASS,
          "proposal",
          { ceremonySlug: this.slug, subClassNumber: input.subClass },
        );
      }
      // §10A.4: bounded emergency duration MUST be > 0 AND ≤ 30 days
      if (
        input.emergencyDurationSeconds <= 0 ||
        input.emergencyDurationSeconds > 30 * 24 * 60 * 60
      ) {
        throw new CeremonyError(
          CeremonyErrorCode.TRIPWIRE_BYPASS,
          "proposal",
          { ceremonySlug: this.slug, subClassNumber: input.subClass },
        );
      }
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
      subClass: this.input.subClass,
      addedContentRef: this.input.addedContentRef,
      affectedArchetypes: this.input.affectedArchetypes,
      effectiveBlock: this.input.effectiveBlock.toString(),
    });
    return {
      proposalHash: hash,
      target: this.input.registryAddress,
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
      message: "pda_plus_proposal_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        subClassNumber: this.input.subClass,
        governancePath: this.governancePath,
        txHash,
        effectiveBlock: this.input.effectiveBlock,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const expectedEvents: CeremonyEventName[] = this.expectedEvents();

    if (args.context.dryRun) {
      for (const ev of expectedEvents) this.recordEvent(ev);
      await this.logger!.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "execute",
        message: "pda_plus_dry_run_simulated",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
          subClassNumber: this.input.subClass,
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
      message: "pda_plus_executed",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        subClassNumber: this.input.subClass,
        txHash,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    for (const ev of this.expectedEvents()) {
      if (!this.emittedEvents.includes(ev)) {
        throw new CeremonyError(
          CeremonyErrorCode.REGISTRY_COLLISION,
          "verify",
          {
            ceremonyId: args.context.ceremonyId,
            ceremonySlug: this.slug,
            proposalHash: p.proposalHash,
            subClassNumber: this.input.subClass,
          },
        );
      }
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "verify",
      message: "pda_plus_verified",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        subClassNumber: this.input.subClass,
      },
    });
  }

  private expectedEvents(): CeremonyEventName[] {
    switch (this.input.subClass) {
      case PdaPlusSubClass.ADDITION_7D:
        return ["EntryAdded"];
      case PdaPlusSubClass.DEPRECATION_MULTISIG:
        return ["DeprecationFlagSet", "DisclosurePublished"];
      case PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER:
        return ["SecurityCouncilSuspended"];
      case PdaPlusSubClass.CONSTRAINT_ADJUSTMENT:
        return ["EntryAdded"];
      case PdaPlusSubClass.RULE_ADDITION:
        return ["EntryAdded", "RoleGranted"];
      default:
        return [];
    }
  }
}

function governancePathForSubClass(sub: PdaPlusSubClass): GovernancePath {
  switch (sub) {
    case PdaPlusSubClass.ADDITION_7D:
    case PdaPlusSubClass.CONSTRAINT_ADJUSTMENT:
    case PdaPlusSubClass.RULE_ADDITION:
      return GovernancePath.TIMELOCK_7D_ADDITION;
    case PdaPlusSubClass.DEPRECATION_MULTISIG:
      return GovernancePath.EXPEDITED_24H_DEPRECATION;
    case PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER:
      return GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION;
    default:
      return GovernancePath.TIMELOCK_7D_ADDITION;
  }
}
