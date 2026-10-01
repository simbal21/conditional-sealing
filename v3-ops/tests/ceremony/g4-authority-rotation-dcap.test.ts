import { describe, it, expect } from "vitest";
import type { Address, Hex } from "viem";
import {
  G4AuthorityRotationCeremony,
  generateCeremonyId,
  makeContext,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import type { CeremonyError} from "../../src/errors/index.js";
import { CeremonyErrorCode } from "../../src/errors/index.js";
import { STANDARD_TIMELOCK_DELAY_SECONDS } from "../../src/multisig/index.js";
import type { DcapAcceptancePacket } from "../../src/m3-imports.js";

const REGISTRY: Address = "0x1234567890123456789012345678901234567890";
const G4_REF = ("0x" + "10".repeat(32)) as Hex;

// §4.2.1 mandates the acceptance gate is re-run "immediately before execution"
// if the 7-day timelock makes collateral stale. The test packet is therefore
// re-issued at a freshness ~just before execute (post timelock advance).
const POST_TIMELOCK_OFFSET_SECONDS = STANDARD_TIMELOCK_DELAY_SECONDS + 30;

function basePacket(): DcapAcceptancePacket {
  return {
    g4AuthorityRef: G4_REF,
    phase: 2,
    authorityPubkey: ("0x" + "11".repeat(32)) as Hex,
    teeMeasurement: ("0x" + "12".repeat(32)) as Hex,
    dcapVerifierRef: ("0x" + "13".repeat(32)) as Hex,
    effectiveBlock: 2_000_000n,
    metadataHash: ("0x" + "14".repeat(32)) as Hex,
    admissionAuthoritativeMode: "snark-backed",
    acceptedTcbStatuses: ["UpToDate"],
    vendorFamilyClassification: "intel-sgx-amber",
    litG4DisjointnessVerified: true,
    collateralFreshnessUnix:
      Math.floor(Date.now() / 1000) + POST_TIMELOCK_OFFSET_SECONDS,
    quoteProofDigest: ("0x" + "15".repeat(32)) as Hex,
    userDataDigest: ("0x" + "16".repeat(32)) as Hex,
  };
}

function buildCeremony(packet: DcapAcceptancePacket | null): G4AuthorityRotationCeremony {
  return new G4AuthorityRotationCeremony({
    registryAddress: REGISTRY,
    phase: 2,
    g4AuthorityRef: G4_REF,
    authorityPubkey: ("0x" + "11".repeat(32)) as Hex,
    teeMeasurement: packet?.teeMeasurement ?? null,
    dcapVerifierRef: packet?.dcapVerifierRef ?? null,
    dcapAcceptancePacket: packet,
    metadataHash: ("0x" + "14".repeat(32)) as Hex,
    effectiveBlock: 2_000_000n,
    tombstoneBlockForOld: 2_000_000n,
    oldEntryRef: ("0x" + "17".repeat(32)) as Hex,
    addEntryCalldata: ("0x" + "18".repeat(32)) as Hex,
    salt: ("0x" + "19".repeat(32)) as Hex,
  });
}

async function runLive(
  ceremony: G4AuthorityRotationCeremony,
): Promise<CeremonyError | undefined> {
  const chain = new MockChain({
    initialBlock: 1_000_000n,
    initialTimestamp: BigInt(Math.floor(Date.now() / 1000)),
  });
  chain.pendingEvents.push({ eventName: "EntryAdded" });
  chain.pendingEvents.push({ eventName: "EntryTombstoned" });
  const orig = chain.scheduleTimelock.bind(chain);
  chain.scheduleTimelock = async (a) => {
    const r = await orig(a);
    chain.advanceSeconds(BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60));
    return r;
  };
  const ctx = makeContext({
    ceremonyId: generateCeremonyId(ceremony.slug),
    commitBlock: 1_500_000n,
    chainId: 84532,
    dryRun: false,
    slug: ceremony.slug,
  });
  try {
    await ceremony.run({ context: ctx, chain });
    return undefined;
  } catch (e) {
    return e as CeremonyError;
  }
}

/**
 * §4.2.1 Phase 2 G4 DCAP acceptance gate tests. Every failure path
 * surfaces as `CEREMONY_ERR_TRIPWIRE_BYPASS` at execute stage so no
 * partial state change happens.
 */
describe("g4-authority-rotation Phase 2 DCAP acceptance gate (§4.2.1)", () => {
  it("valid packet → ceremony succeeds", async () => {
    const ceremony = buildCeremony(basePacket());
    const err = await runLive(ceremony);
    expect(err).toBeUndefined();
  });

  it("packet === null → TRIPWIRE_BYPASS", async () => {
    const ceremony = buildCeremony(null);
    const err = await runLive(ceremony);
    expect(err?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("g4AuthorityRef mismatch → TRIPWIRE_BYPASS", async () => {
    const packet = { ...basePacket(), g4AuthorityRef: ("0x" + "00".repeat(32)) as Hex };
    const ceremony = buildCeremony(packet);
    const err = await runLive(ceremony);
    expect(err?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("phase !== 2 → TRIPWIRE_BYPASS", async () => {
    const packet = { ...basePacket(), phase: 1 as unknown as 2 };
    const ceremony = buildCeremony(packet);
    const err = await runLive(ceremony);
    expect(err?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("admissionAuthoritativeMode unknown → TRIPWIRE_BYPASS", async () => {
    const packet = {
      ...basePacket(),
      admissionAuthoritativeMode: "unknown-mode" as unknown as DcapAcceptancePacket["admissionAuthoritativeMode"],
    };
    const ceremony = buildCeremony(packet);
    const err = await runLive(ceremony);
    expect(err?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("vendor-family classification ambiguous → fail-closed TRIPWIRE_BYPASS", async () => {
    const packet = { ...basePacket(), vendorFamilyClassification: "ambiguous" };
    const ceremony = buildCeremony(packet);
    const err = await runLive(ceremony);
    expect(err?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("Lit/G4 cross-vendor disjointness fails → TRIPWIRE_BYPASS", async () => {
    const packet = { ...basePacket(), litG4DisjointnessVerified: false };
    const ceremony = buildCeremony(packet);
    const err = await runLive(ceremony);
    expect(err?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("no accepted TCB statuses → TRIPWIRE_BYPASS", async () => {
    const packet = { ...basePacket(), acceptedTcbStatuses: [] };
    const ceremony = buildCeremony(packet);
    const err = await runLive(ceremony);
    expect(err?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("stale collateral (older than 24h) → TRIPWIRE_BYPASS", async () => {
    const packet = {
      ...basePacket(),
      collateralFreshnessUnix: Math.floor(Date.now() / 1000) - 48 * 60 * 60,
    };
    const ceremony = buildCeremony(packet);
    const err = await runLive(ceremony);
    expect(err?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });
});
