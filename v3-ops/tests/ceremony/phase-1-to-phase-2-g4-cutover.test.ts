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

function packet(): DcapAcceptancePacket {
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
  };
}

function buildCeremony(p: DcapAcceptancePacket | null = packet()): Phase1To2CutoverCeremony {
  return new Phase1To2CutoverCeremony({
    registryAddress: REG,
    newPhase2AuthorityRef: REF,
    authorityPubkey: H(0x10),
    teeMeasurement: H(0x11),
    dcapVerifierRef: H(0x12),
    dcapAcceptancePacket: p ?? packet(),
    metadataHash: H(0x13),
    cutoverEffectiveBlock: 2_000_000n,
    phase1HistoricalPolicyHash: H(0x40),
    addEntryCalldata: H(0x50),
    salt: H(0x51),
  });
}

describe("phase-1-to-phase-2-g4-cutover (§15)", () => {
  it("dry-run with valid packet completes + announces", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = buildCeremony();
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
  });

  it("§4.2.1 gate failure (lit_g4_overlap) → TRIPWIRE_BYPASS", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const p = packet();
    const bad = { ...p, litG4DisjointnessVerified: false };
    const ceremony = buildCeremony(bad);
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

  it("ambiguous vendor-family classification → TRIPWIRE_BYPASS", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const p = packet();
    const ceremony = buildCeremony({ ...p, vendorFamilyClassification: "ambiguous" });
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

  it("live execution after timelock emits EntryAdded", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    chain.pendingEvents.push({ eventName: "EntryAdded" });
    const orig = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (a) => {
      const r = await orig(a);
      chain.advanceSeconds(BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60));
      return r;
    };
    const ceremony = buildCeremony();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
  });
});
