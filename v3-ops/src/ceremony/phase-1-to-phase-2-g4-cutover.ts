import type { Address, Hex } from "viem";
import { Ceremony, delayForPath, type CeremonyRunArgs } from "./base.js";
import { proposalHash } from "./proposal-hash.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import type { DcapAcceptancePacket } from "../m3-imports.js";

/**
 * §15 — Phase 1 → Phase 2 G4 cutover.
 *
 * M7 ships this as a runbook + dry-run only. Actual cutover is an
 * operational decision (made when partner signing/funding makes Phase 2
 * operationally available). The §15.4 partner-ready guardrail asserts that
 * legal-effect or partner-ready commits are REJECTED under Phase 1.
 *
 * The cutover is structurally a Phase 2 G4AuthorityRegistry addition (i.e.
 * a g4-authority-rotation invocation), but with the §15.5 announcement
 * obligation: effective block, Phase 2 authority ref, and Phase 1 historical-
 * verification policy must be published.
 *
 * Phase 1 entries remain valid for Phase 1 dev commits after cutover.
 * They are NOT upgraded into legal-effect Phase 2 commits.
 */
export interface Phase1To2CutoverInput {
  readonly registryAddress: Address;
  readonly newPhase2AuthorityRef: Hex;
  readonly authorityPubkey: Hex;
  readonly teeMeasurement: Hex;
  readonly dcapVerifierRef: Hex;
  readonly dcapAcceptancePacket: DcapAcceptancePacket;
  readonly metadataHash: Hex;
  readonly cutoverEffectiveBlock: bigint;
  readonly phase1HistoricalPolicyHash: Hex;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class Phase1To2CutoverCeremony extends Ceremony {
  override readonly slug = "phase-1-to-phase-2-g4-cutover";
  override readonly specSection = "§15";
  override readonly catalogRowNumber = 2; // folds under §4 catalog row in App. A
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  private readonly input: Phase1To2CutoverInput;

  constructor(input: Phase1To2CutoverInput) {
    super();
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
      phase: 2,
      newPhase2AuthorityRef: this.input.newPhase2AuthorityRef,
      authorityPubkey: this.input.authorityPubkey,
      teeMeasurement: this.input.teeMeasurement,
      dcapVerifierRef: this.input.dcapVerifierRef,
      cutoverEffectiveBlock: this.input.cutoverEffectiveBlock.toString(),
      phase1HistoricalPolicyHash: this.input.phase1HistoricalPolicyHash,
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
      message: "cutover_queued",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        phase: 2,
        g4AuthorityRef: this.input.newPhase2AuthorityRef,
        effectiveBlock: this.input.cutoverEffectiveBlock,
        txHash,
      },
    });
  }

  async execute(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    // §4.2.1 DCAP acceptance gate fires regardless of dry-run vs live —
    // the gate verifies acceptance-packet structural integrity offline.
    await this.runDcapAcceptanceGate(args);

    if (args.context.dryRun) {
      this.recordEvent("EntryAdded");
      await this.logger!.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "execute",
        message: "cutover_dry_run_simulated",
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
      message: "cutover_executed",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        txHash,
        phase: 2,
      },
    });
  }

  async verify(args: CeremonyRunArgs, p: Awaited<ReturnType<this["proposal"]>>): Promise<void> {
    const expected: CeremonyEventName = "EntryAdded";
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
      message: "cutover_announcement_obligations_marked",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        proposalHash: p.proposalHash,
        // §15.5 announcement obligations — these hashes anchor the
        // partner-facing announcement S2-5/S3-1 must publish.
        effectiveBlock: this.input.cutoverEffectiveBlock,
        // phase1HistoricalPolicyHash captures the historical-verification
        // policy for old Phase 1 dev commits per §15.3.
      },
    });
  }

  private async runDcapAcceptanceGate(args: CeremonyRunArgs): Promise<void> {
    const packet = this.input.dcapAcceptancePacket;
    const failures: string[] = [];
    if (packet.phase !== 2) failures.push("phase_mismatch");
    if (packet.g4AuthorityRef !== this.input.newPhase2AuthorityRef) failures.push("ref_mismatch");
    if (
      packet.admissionAuthoritativeMode !== "snark-backed" &&
      packet.admissionAuthoritativeMode !== "on-chain-verifier"
    ) {
      failures.push("unknown_admission_mode");
    }
    if (
      packet.vendorFamilyClassification === "" ||
      packet.vendorFamilyClassification === "ambiguous"
    ) {
      failures.push("ambiguous_vendor_family");
    }
    if (!packet.litG4DisjointnessVerified) failures.push("lit_g4_overlap");
    if (packet.acceptedTcbStatuses.length === 0) failures.push("no_tcb_statuses_accepted");
    const nowUnix = Number(await args.chain.readBlockTimestamp());
    if (nowUnix - packet.collateralFreshnessUnix > 24 * 60 * 60) {
      failures.push("stale_collateral");
    }
    if (failures.length > 0) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "execute",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          phase: 2,
          governancePath: failures.join(","),
        },
      );
    }
  }
}
