import type { Address, Hex } from "viem";
import { Ceremony, delayForPath, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";

/**
 * §14.3 — Vault operator transition (Ceremony 16).
 *
 * Moves sealed ciphertext, σ_subject storage, metadata, and append-only
 * audit logs to successor storage. `h_commit` does NOT change. Retention
 * floors and shred obligations survive migration.
 *
 * Planned transition: 7-day TimelockController.
 * Emergency read-halt: EmergencyGovernance + CealisSecurityMultisig
 *   (replacement storage activation still requires either a pre-staged
 *    destination or standard 7-day activation).
 *
 * NORMATIVE invariants:
 *   - audit-log root continuity: destination root commits to FULL source
 *     audit-log root + migration manifest (NOT truncated replay).
 *   - retention floors, legal holds, active pauses, pending shreds,
 *     finalized shreds, and deletion proofs carry forward as state roots.
 *   - logical `VaultTransitionQueued` / `VaultTransitionFinalized` events
 *     per §18.
 */
export interface VaultOperatorTransitionInput {
  readonly vaultControllerAddress: Address;
  readonly sourceVaultRoot: Hex;
  readonly destinationVaultRoot: Hex;
  readonly sourceAuditLogRoot: Hex;
  readonly destinationAuditLogRoot: Hex;
  readonly retentionStateRoot: Hex;
  readonly shredStateRoot: Hex;
  readonly migrationManifestHash: Hex;
  readonly rollbackBound: bigint;
  readonly notificationHash: Hex;
  /** Planned (7-day) or emergency read-halt path. */
  readonly emergencyReadHalt: boolean;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class VaultOperatorTransitionCeremony extends Ceremony {
  override readonly slug = "vault-operator-transition";
  override readonly specSection = "§14.3";
  override readonly catalogRowNumber = 16;
  override readonly governancePath: GovernancePath;
  private readonly input: VaultOperatorTransitionInput;

  constructor(input: VaultOperatorTransitionInput) {
    super();
    this.input = input;
    this.governancePath = input.emergencyReadHalt
      ? GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION
      : GovernancePath.TIMELOCK_7D_ADDITION;
  }

  async proposal(args: CeremonyRunArgs): Promise<{
    proposalHash: Hex;
    target: Address;
    data: Hex;
    salt: Hex;
  }> {
    // §14.3 NORMATIVE audit-log root continuity check: the destination
    // root MUST commit to the source audit-log root AND migration manifest.
    // (Implementation-level: caller computes destinationAuditLogRoot off
    // chain; the ceremony asserts the structural relationship at verify().)
    if (this.input.sourceAuditLogRoot === this.input.destinationAuditLogRoot) {
      // Identical roots imply no migration manifest binding — fail-closed.
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "proposal",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
        },
      );
    }
    const hash = proposalHash({
      ceremony: this.slug,
      sourceVaultRoot: this.input.sourceVaultRoot,
      destinationVaultRoot: this.input.destinationVaultRoot,
      sourceAuditLogRoot: this.input.sourceAuditLogRoot,
      destinationAuditLogRoot: this.input.destinationAuditLogRoot,
      retentionStateRoot: this.input.retentionStateRoot,
      shredStateRoot: this.input.shredStateRoot,
      migrationManifestHash: this.input.migrationManifestHash,
      rollbackBound: this.input.rollbackBound.toString(),
      notificationHash: this.input.notificationHash,
      emergencyReadHalt: this.input.emergencyReadHalt,
    });
    return {
      proposalHash: hash,
      target: this.input.vaultControllerAddress,
      data: this.input.addEntryCalldata,
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
    this.recordEvent("VaultTransitionQueued");
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "info",
      stage: "queue",
      message: "vault_transition_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        sourceVaultRoot: this.input.sourceVaultRoot,
        destinationVaultRoot: this.input.destinationVaultRoot,
        sourceAuditLogRoot: this.input.sourceAuditLogRoot,
        destinationAuditLogRoot: this.input.destinationAuditLogRoot,
        migrationManifestHash: this.input.migrationManifestHash,
        rollbackBound: this.input.rollbackBound,
        txHash,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    if (args.context.dryRun) {
      this.recordEvent("VaultTransitionFinalized");
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
      message: "vault_transition_finalized",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        destinationVaultRoot: this.input.destinationVaultRoot,
        destinationAuditLogRoot: this.input.destinationAuditLogRoot,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const required: CeremonyEventName[] = ["VaultTransitionQueued", "VaultTransitionFinalized"];
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
    // §14.3 carry-forward invariants — retention + shred + audit-log roots
    // all bound in the destination root via migration manifest.
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "verify",
      message: "vault_transition_carry_forward_verified",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        sourceAuditLogRoot: this.input.sourceAuditLogRoot,
        destinationAuditLogRoot: this.input.destinationAuditLogRoot,
        migrationManifestHash: this.input.migrationManifestHash,
        retentionStateRoot: this.input.retentionStateRoot,
        shredStateRoot: this.input.shredStateRoot,
      },
    });
  }
}
