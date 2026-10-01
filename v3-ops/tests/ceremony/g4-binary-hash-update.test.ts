import { describe, it, expect, beforeEach } from "vitest";
import {
  G4BinaryHashUpdateCeremony,
  makeContext,
  generateCeremonyId,
  type CeremonyOutcome,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import type { Address, Hex } from "viem";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";
import { STANDARD_TIMELOCK_DELAY_SECONDS } from "../../src/multisig/index.js";

const REGISTRY: Address = "0x1234567890123456789012345678901234567890";

function makeCeremony(): G4BinaryHashUpdateCeremony {
  return new G4BinaryHashUpdateCeremony({
    registryAddress: REGISTRY,
    g4AuthorityRef: ("0x" + "01".repeat(32)) as Hex,
    binaryHash: ("0x" + "aa".repeat(32)) as Hex,
    sourceCommitDigest: ("0x" + "bb".repeat(32)) as Hex,
    buildEnvDigest: ("0x" + "cc".repeat(32)) as Hex,
    testVectorDigest: ("0x" + "dd".repeat(32)) as Hex,
    metadataHash: ("0x" + "ee".repeat(32)) as Hex,
    effectiveBlock: 2_000_000n,
    addEntryCalldata: ("0x" + "ff".repeat(64)) as Hex,
    salt: ("0x" + "11".repeat(32)) as Hex,
  });
}

let chain: MockChain;

beforeEach(() => {
  chain = new MockChain({ initialBlock: 1_000_000n });
});

describe("g4-binary-hash-update (§3)", () => {
  it("happy path dry-run reaches complete and emits EntryAdded", async () => {
    const ceremony = makeCeremony();
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
    expect(outcome.stagesReached).toContain("complete");
    expect(outcome.opId).not.toBeNull();
  });

  it("happy path live execution after 7-day delay", async () => {
    const ceremony = makeCeremony();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    // Pre-load events the chain will emit on execute
    chain.pendingEvents.push({ eventName: "EntryAdded" });
    // Need to advance the clock past the 7-day delay BEFORE execute is called.
    // The ceremony queues at t=0 and immediately tries to execute — that
    // would fail with the mock's TIMELOCK_NOT_EXPIRED check. We patch the
    // mock's clock to jump on schedule completion instead.
    const originalSchedule = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (args) => {
      const result = await originalSchedule(args);
      chain.advanceSeconds(BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60));
      return result;
    };
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
    expect(outcome.emittedEvents).toContain("EntryAdded");
    expect(outcome.txHashes.length).toBeGreaterThanOrEqual(2); // schedule + execute
  });

  it("missing event at execute → REGISTRY_COLLISION", async () => {
    const ceremony = makeCeremony();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    // Do NOT pre-load `EntryAdded` — verify() should catch the absence.
    const originalSchedule = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (args) => {
      const result = await originalSchedule(args);
      chain.advanceSeconds(BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60));
      return result;
    };
    let caught: CeremonyError | undefined;
    try {
      await ceremony.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(caught).toBeInstanceOf(CeremonyError);
    expect(caught!.code).toBe(CeremonyErrorCode.REGISTRY_COLLISION);
  });

  it("deprecation flag set on the new entry post-execute → REGISTRY_COLLISION", async () => {
    const ceremony = makeCeremony();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    chain.pendingEvents.push({ eventName: "EntryAdded" });
    const originalSchedule = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (args) => {
      const result = await originalSchedule(args);
      chain.advanceSeconds(BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60));
      return result;
    };
    // Pre-build the proposal to learn the proposal hash, then set the deprecation flag.
    const proposalPreview = await ceremony.proposal({ context: ctx, chain });
    chain.setDeprecationFlag(`G4AuthorityRegistry:${proposalPreview.proposalHash}`, {
      reasonCode: 0x07,
      disclosureCid: "bafy-disclosure",
    });
    let outcome: CeremonyOutcome | undefined;
    let caught: CeremonyError | undefined;
    try {
      outcome = await ceremony.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(outcome).toBeUndefined();
    expect(caught).toBeInstanceOf(CeremonyError);
    expect(caught!.code).toBe(CeremonyErrorCode.REGISTRY_COLLISION);
  });
});
