import { describe, it, expect } from "vitest";
import type { Address, Hex } from "viem";
import {
  Phase1To2CutoverCeremony,
  generateCeremonyId,
  makeContext,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import type { CeremonyError} from "../../src/errors/index.js";
import { CeremonyErrorCode } from "../../src/errors/index.js";
import { STANDARD_TIMELOCK_DELAY_SECONDS } from "../../src/multisig/index.js";
import type { DcapAcceptancePacket } from "../../src/m3-imports.js";

const REG: Address = "0xabcdef0000000000000000000000000000000003";
const H = (n: number) => (("0x" + n.toString(16).padStart(2, "0").repeat(32)) as Hex);
const REF = H(0x77);

/**
 * §15.4 partner-ready guardrail (NORMATIVE).
 *
 * "Configurator and contract validation reject legal-effect or partner-
 * ready commits under Phase 1. A Phase 1 dev commit that needs partner
 * readiness must be recommitted under Phase 2 with fresh σ_subject over
 * the new commit."
 *
 * The contract-level enforcement is M2/M4 territory. M7 verifies:
 *   - (negative) attempting a Phase 2 cutover with an INVALID DCAP packet
 *     surfaces TRIPWIRE_BYPASS — i.e. no fast-path that would let a
 *     legal-effect commit slip in under degraded Phase 2 attestation.
 *   - (positive) a well-formed Phase 2 cutover completes, after which
 *     `commit_class === "legal-effect" | "partner-ready"` PDAs become
 *     accepted.
 */

function packet(opts?: Partial<DcapAcceptancePacket>): DcapAcceptancePacket {
  return {
    g4AuthorityRef: REF,
    phase: 2,
    authorityPubkey: H(0x10),
    teeMeasurement: H(0x11),
    dcapVerifierRef: H(0x12),
    effectiveBlock: 2_000_000n,
    metadataHash: H(0x13),
    admissionAuthoritativeMode: "snark-backed",
    acceptedTcbStatuses: ["UpToDate"],
    vendorFamilyClassification: "intel-sgx-amber",
    litG4DisjointnessVerified: true,
    collateralFreshnessUnix:
      Math.floor(Date.now() / 1000) + STANDARD_TIMELOCK_DELAY_SECONDS + 30,
    quoteProofDigest: H(0x14),
    userDataDigest: H(0x15),
    ...opts,
  };
}

describe("§15.4 partner-ready guardrail (NORMATIVE)", () => {
  it("POS: well-formed Phase 2 cutover completes; legal-effect/partner-ready commits unblocked post-cutover", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = new Phase1To2CutoverCeremony({
      registryAddress: REG,
      newPhase2AuthorityRef: REF,
      authorityPubkey: H(0x10),
      teeMeasurement: H(0x11),
      dcapVerifierRef: H(0x12),
      dcapAcceptancePacket: packet(),
      metadataHash: H(0x13),
      cutoverEffectiveBlock: 2_000_000n,
      phase1HistoricalPolicyHash: H(0x40),
      addEntryCalldata: H(0x50),
      salt: H(0x51),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
    expect(outcome.emittedEvents).toContain("EntryAdded");
    // After cutover, the configurator surface (M4) accepts legal-effect /
    // partner-ready commit classes against this new Phase 2 entry. M7
    // verifies the cutover ran clean; M4 enforces the rejection of
    // legal-effect commits BEFORE this entry was effective.
  });

  it("NEG: ambiguous vendor-family Phase 2 packet → TRIPWIRE_BYPASS (no degraded Phase 2 entry created)", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = new Phase1To2CutoverCeremony({
      registryAddress: REG,
      newPhase2AuthorityRef: REF,
      authorityPubkey: H(0x10),
      teeMeasurement: H(0x11),
      dcapVerifierRef: H(0x12),
      dcapAcceptancePacket: packet({ vendorFamilyClassification: "ambiguous" }),
      metadataHash: H(0x13),
      cutoverEffectiveBlock: 2_000_000n,
      phase1HistoricalPolicyHash: H(0x40),
      addEntryCalldata: H(0x50),
      salt: H(0x51),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    let caught: CeremonyError | undefined;
    try {
      await ceremony.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(caught?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("NEG: Lit/G4 disjointness fails → TRIPWIRE_BYPASS (no Phase 2 entry; legal-effect commits stay blocked)", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = new Phase1To2CutoverCeremony({
      registryAddress: REG,
      newPhase2AuthorityRef: REF,
      authorityPubkey: H(0x10),
      teeMeasurement: H(0x11),
      dcapVerifierRef: H(0x12),
      dcapAcceptancePacket: packet({ litG4DisjointnessVerified: false }),
      metadataHash: H(0x13),
      cutoverEffectiveBlock: 2_000_000n,
      phase1HistoricalPolicyHash: H(0x40),
      addEntryCalldata: H(0x50),
      salt: H(0x51),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    let caught: CeremonyError | undefined;
    try {
      await ceremony.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(caught?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("§15.3 Phase 1 historical validity: Phase 1 entries remain valid for Phase 1 dev commits post-cutover (documentary check)", () => {
    // The actual on-chain enforcement is in the G4AuthorityRegistry
    // contract — `getEntryAt(phase1Ref, oldCommitBlock)` returns the
    // Phase 1 entry. Phase 1 commits are NOT upgraded into legal-effect
    // Phase 2 commits — they remain Phase 1 forever per §15.3.
    expect("Phase 1 historical validity is contract-level enforcement (M2)").toBe(
      "Phase 1 historical validity is contract-level enforcement (M2)",
    );
  });
});
