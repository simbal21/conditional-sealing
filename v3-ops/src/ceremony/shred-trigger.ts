import type { Address, Hex } from "viem";
import { Ceremony, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import { ShredAuthority } from "../types/authority-enums.js";
import type { VaultClient } from "../adapters/index.js";

/**
 * §11 — Shred triggering semantics per authority mode.
 *
 * 5 authority modes per §11.1 + §11.2: Subject / Joint / Operator / Timelock /
 * Disabled. Authority is necessary but not sufficient — the shred CONDITION
 * must also evaluate true AND the mandatory guardrail
 * `post_challenge_reveal_in_progress == false` must hold.
 *
 * §11.3 triple block: G1 refuses future reveal authorization, G4 refuses
 * σ_G4 for future or still-haltable attempts, vault deletes ciphertext.
 *
 * §11.4 MANDATORY guardrail: every shred condition AND-composes the explicit
 * predicate `post_challenge_reveal_in_progress == false`. PDA+ guardrail;
 * NOT partner-configurable. This check fires BEFORE the authority check so
 * the guardrail can NEVER be bypassed by an authority-correct request.
 *
 * §11.5: `proof_shred` is a public verification token, NOT σ / share / DEK
 * / reveal authorization.
 *
 * §11.7: finalization requires authority proof + condition true +
 * `post_challenge_reveal_in_progress == false` + challenge-window completion
 * if non-zero + minimum shred latency elapsed + no blocking G4/legal/refusal
 * state that forces pause rather than shred. Disabled mode NEVER finalizes.
 */
export interface ShredTriggerInput {
  readonly conditionEngineAddress: Address;
  readonly shredRegistryAddress: Address;
  readonly hCommit: Hex;
  readonly authorityMode: ShredAuthority;
  /** Authority proof bytes (σ_subject for Subject, joint sig for Joint, etc.). */
  readonly authorityProof: Hex;
  /** Condition module result — pre-evaluated by ConditionEngine. */
  readonly conditionEvaluatedTrue: boolean;
  /** §11.4 mandatory guardrail input — verified from ChallengeRegistry. */
  readonly postChallengeRevealInProgress: boolean;
  /** §11.7: challenge window must be completed if non-zero. */
  readonly challengeWindowCompleted: boolean;
  /** §11.7: minimum shred latency since trigger must have elapsed. */
  readonly minLatencyBlocksElapsed: boolean;
  /** Reason digest for the shred. PII allow-list compatible. */
  readonly reasonDigest: Hex;
  /** PDA-bound legal basis digest (Operator mode only). */
  readonly legalBasisDigest: Hex | null;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
  readonly vaultClient: VaultClient;
}

export class ShredTriggerCeremony extends Ceremony {
  override readonly slug = "shred-trigger";
  override readonly specSection = "§11";
  override readonly catalogRowNumber = 11;
  override readonly governancePath: GovernancePath;
  private readonly input: ShredTriggerInput;
  private proofShred: Hex | null = null;

  constructor(input: ShredTriggerInput) {
    super();
    this.input = input;
    // Shred timelock varies per authority mode; map to closest §13.6 slot.
    this.governancePath =
      input.authorityMode === ShredAuthority.TIMELOCK
        ? GovernancePath.TIMELOCK_7D_ADDITION
        : GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION;
  }

  async proposal(args: CeremonyRunArgs): Promise<{
    proposalHash: Hex;
    target: Address;
    data: Hex;
    salt: Hex;
  }> {
    // §11.2 Disabled mode never authorizes — reject at proposal stage.
    if (this.input.authorityMode === ShredAuthority.DISABLED) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "proposal",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          authorityMode: this.input.authorityMode,
          hCommit: this.input.hCommit,
        },
      );
    }
    // §11.4 MANDATORY guardrail fires BEFORE authority check so the
    // tripwire is unbypassable even with a valid authority proof.
    if (this.input.postChallengeRevealInProgress) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "proposal",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          authorityMode: this.input.authorityMode,
          hCommit: this.input.hCommit,
        },
      );
    }
    // Operator mode requires a PDA-bound legal-basis digest per §11.2.
    if (
      this.input.authorityMode === ShredAuthority.OPERATOR &&
      this.input.legalBasisDigest === null
    ) {
      throw new CeremonyError(
        CeremonyErrorCode.QUORUM_MISSING,
        "proposal",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          authorityMode: this.input.authorityMode,
          hCommit: this.input.hCommit,
        },
      );
    }
    const hash = proposalHash({
      ceremony: this.slug,
      hCommit: this.input.hCommit,
      authorityMode: this.input.authorityMode,
      reasonDigest: this.input.reasonDigest,
    });
    return {
      proposalHash: hash,
      target: this.input.conditionEngineAddress,
      data: this.input.addEntryCalldata,
      salt: this.input.salt,
    };
  }

  async queue(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    // §11.7 finalization conditions checked at queue stage.
    if (!this.input.conditionEvaluatedTrue) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "queue",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          authorityMode: this.input.authorityMode,
        },
      );
    }
    if (!this.input.challengeWindowCompleted) {
      throw new CeremonyError(
        CeremonyErrorCode.TIMELOCK_NOT_EXPIRED,
        "queue",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          authorityMode: this.input.authorityMode,
        },
      );
    }
    if (!this.input.minLatencyBlocksElapsed) {
      throw new CeremonyError(
        CeremonyErrorCode.TIMELOCK_NOT_EXPIRED,
        "queue",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          authorityMode: this.input.authorityMode,
        },
      );
    }

    // Emit ShredRequested either by Safe multisig (Operator with legal
    // basis) or by direct on-chain call (Subject/Joint/Timelock).
    const { txHash } = await args.chain.scheduleTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      salt: p.salt,
      delaySeconds: 0n, // shred uses per-PDA min latency, not 7-day delay
    });
    this.recordTx(txHash);
    this.recordEvent("ShredRequested");
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "queue",
      message: "shred_requested",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        hCommit: this.input.hCommit,
        authorityMode: this.input.authorityMode,
        reasonCode: 0,
        txHash,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    // §11.3 triple block:
    //   1. G1 refuses future reveal auth — ShredRegistry on-chain state
    //   2. G4 refuses σ_G4 — registry state mirrored to G4 by event listener
    //   3. Vault deletes ciphertext — vaultClient.deleteCiphertext(hCommit)
    if (args.context.dryRun) {
      this.proofShred = ("0x" + "dd".repeat(32)) as Hex;
      this.recordEvent("ShredFinalized");
      await this.logger!.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "execute",
        message: "shred_dry_run_simulated",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: p.proposalHash,
          hCommit: this.input.hCommit,
          authorityMode: this.input.authorityMode,
          dryRun: true,
        },
      });
      return;
    }

    // 1+2: on-chain state change via TimelockController.execute.
    const { txHash, events } = await args.chain.executeTimelock({
      target: p.target,
      value: 0n,
      data: p.data,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      salt: p.salt,
    });
    this.recordTx(txHash);
    for (const ev of events) this.recordEvent(ev.eventName);

    // 3: vault ciphertext delete (M5 vault API — interface stub at M7).
    const { deletionProof, timestampUnix } = await this.input.vaultClient.deleteCiphertext(
      this.input.hCommit,
    );
    this.proofShred = deletionProof;
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "execute",
      message: "shred_finalized",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        hCommit: this.input.hCommit,
        authorityMode: this.input.authorityMode,
        txHash,
        timestampUnix,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const required: CeremonyEventName[] = ["ShredRequested", "ShredFinalized"];
    for (const ev of required) {
      if (!this.emittedEvents.includes(ev)) {
        throw new CeremonyError(
          CeremonyErrorCode.REGISTRY_COLLISION,
          "verify",
          {
            ceremonyId: args.context.ceremonyId,
            ceremonySlug: this.slug,
            proposalHash: p.proposalHash,
            authorityMode: this.input.authorityMode,
          },
        );
      }
    }
    if (this.proofShred === null) {
      throw new CeremonyError(
        CeremonyErrorCode.REGISTRY_COLLISION,
        "verify",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
        },
      );
    }
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "verify",
      message: "proof_shred_published",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        hCommit: this.input.hCommit,
        authorityMode: this.input.authorityMode,
        // proof_shred is a public verification token, not key material —
        // safe to surface in audit log.
      },
    });
  }

  /** Expose proof_shred for callers (M5 partner-facing surface) after run completes. */
  getProofShred(): Hex | null {
    return this.proofShred;
  }
}
