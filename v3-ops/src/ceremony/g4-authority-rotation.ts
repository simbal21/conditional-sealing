import type { Address, Hex } from "viem";
import { RegistryAdditionCeremony, type RegistryAddProposalInput } from "./registry-add-template.js";
import { GovernancePath, type CeremonyEventName } from "../types/ceremony.js";
import type { CeremonyRunArgs } from "./base.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import type { DcapAcceptancePacket } from "../m3-imports.js";

/**
 * §4 — G4 authority key rotation.
 *
 * Phase 2 rotations require a §4.2.1 DCAP acceptance gate to fire BEFORE
 * TimelockController.execute. Stale collateral / TCB / ambiguous vendor-
 * family → fail-closed REJECTION via the preExecuteHook.
 *
 * Phase 1 rotations use the same proposal flow but skip the DCAP gate
 * (Phase 1 binary-hash + sealed-code only; no TEE attestation).
 *
 * Operational tuple per §4.2: `(hash, effective_block, tombstone_block)`.
 * Old key remains valid for historical verification within its tuple
 * interval (§4.6).
 */
export interface G4AuthorityRotationInput {
  readonly registryAddress: Address;
  readonly phase: 1 | 2;
  readonly g4AuthorityRef: Hex;
  readonly authorityPubkey: Hex;
  /** Phase 2 only: TEE measurement. Required if phase === 2. */
  readonly teeMeasurement: Hex | null;
  /** Phase 2 only: DCAP verifier ref. Required if phase === 2. */
  readonly dcapVerifierRef: Hex | null;
  /** Phase 2 only: full acceptance packet evaluated by the gate. */
  readonly dcapAcceptancePacket: DcapAcceptancePacket | null;
  readonly metadataHash: Hex;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlockForOld: bigint;
  readonly oldEntryRef: Hex;
  readonly addEntryCalldata: Hex;
  readonly salt: Hex;
}

export class G4AuthorityRotationCeremony extends RegistryAdditionCeremony {
  override readonly slug = "g4-authority-rotation";
  override readonly specSection = "§4";
  override readonly catalogRowNumber = 2;
  override readonly governancePath = GovernancePath.TIMELOCK_7D_ADDITION;
  override readonly inputBuilder: (a: CeremonyRunArgs) => Promise<RegistryAddProposalInput>;

  constructor(input: G4AuthorityRotationInput) {
    super();
    this.inputBuilder = async (_args) => ({
      registry: "G4AuthorityRegistry",
      contractAddress: input.registryAddress,
      addEntryCalldata: input.addEntryCalldata,
      salt: input.salt,
      predecessor: ("0x" + "00".repeat(32)) as Hex,
      payload: {
        phase: input.phase,
        g4AuthorityRef: input.g4AuthorityRef,
        authorityPubkey: input.authorityPubkey,
        teeMeasurement: input.teeMeasurement ?? null,
        dcapVerifierRef: input.dcapVerifierRef ?? null,
        metadataHash: input.metadataHash,
        effectiveBlock: input.effectiveBlock.toString(),
        tombstoneBlockForOld: input.tombstoneBlockForOld.toString(),
        oldEntryRef: input.oldEntryRef,
      },
      expectedEvents: ["EntryAdded", "EntryTombstoned"] as readonly CeremonyEventName[],
      effectiveBlock: input.effectiveBlock,
      preExecuteHook:
        input.phase === 2
          ? async (args) => {
              await this.runDcapAcceptanceGate(args, input);
            }
          : undefined,
    });
  }

  /**
   * §4.2.1 Phase 2 G4 DCAP acceptance gate. Verifies:
   *   - g4_authority_ref matches the proposal
   *   - phase === 2
   *   - TEE measurement non-null
   *   - DCAP verifier ref non-null
   *   - admission-authoritative mode is one of the two recognized values
   *   - vendor-family classification is unambiguous (fail-closed otherwise)
   *   - Lit/G4 cross-vendor disjointness verified
   *   - collateral freshness within an acceptable window (24h)
   *   - accepted TCB statuses list non-empty
   */
  private async runDcapAcceptanceGate(
    args: CeremonyRunArgs,
    input: G4AuthorityRotationInput,
  ): Promise<void> {
    const packet = input.dcapAcceptancePacket;
    if (packet === null) {
      throw new CeremonyError(
        CeremonyErrorCode.TRIPWIRE_BYPASS,
        "execute",
        {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          phase: 2,
        },
      );
    }
    const failures: string[] = [];
    if (packet.g4AuthorityRef !== input.g4AuthorityRef) failures.push("ref_mismatch");
    if (packet.phase !== 2) failures.push("phase_mismatch");
    if (input.teeMeasurement === null) failures.push("missing_tee_measurement");
    if (input.dcapVerifierRef === null) failures.push("missing_dcap_verifier");
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
    await this.logger!.log({
      ceremonyId: args.context.ceremonyId,
      level: "audit",
      stage: "execute",
      message: "dcap_acceptance_gate_passed",
      fields: {
        ceremonyId: args.context.ceremonyId,
        ceremonySlug: this.slug,
        phase: 2,
        g4AuthorityRef: packet.g4AuthorityRef,
        teeMeasurement: packet.teeMeasurement,
        dcapVerifierRef: packet.dcapVerifierRef,
        metadataHash: packet.metadataHash,
        quoteProofDigest: packet.quoteProofDigest,
      },
    });
  }
}
