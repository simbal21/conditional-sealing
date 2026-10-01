import { expect } from "vitest";
import { MockChain } from "./mock-chain.js";
import {
  generateCeremonyId,
  makeContext,
  type RegistryAdditionCeremony,
} from "../../src/ceremony/index.js";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";
import { STANDARD_TIMELOCK_DELAY_SECONDS } from "../../src/multisig/index.js";
import type { CeremonyEventName } from "../../src/types/ceremony.js";

interface RegistryAdditionTestSuite {
  readonly factory: () => RegistryAdditionCeremony;
  readonly expectedEvents: readonly CeremonyEventName[];
  readonly registryName: string;
  /** Optional advance-time hook for non-standard governance paths */
  readonly delayAdvance?: bigint;
}

/**
 * Run the 4-test suite every registry-addition ceremony shares. Per-spec
 * specifics (DCAP gate, pre-execute hook, sub-class) get their own test
 * files calling this in addition.
 */
export async function runRegistryAdditionSuite(suite: RegistryAdditionTestSuite): Promise<void> {
  // Test 1 — dry-run happy path
  {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = suite.factory();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: ceremony.slug,
    });
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
    expect(outcome.dryRun).toBe(true);
    for (const ev of suite.expectedEvents) {
      expect(outcome.emittedEvents).toContain(ev);
    }
    expect(outcome.stagesReached).toContain("complete");
  }

  // Test 2 — live happy path post timelock delay
  {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = suite.factory();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    for (const ev of suite.expectedEvents) chain.pendingEvents.push({ eventName: ev });
    const advanceSecs = suite.delayAdvance ?? BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60);
    const originalSchedule = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (args) => {
      const result = await originalSchedule(args);
      chain.advanceSeconds(advanceSecs);
      return result;
    };
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
    for (const ev of suite.expectedEvents) {
      expect(outcome.emittedEvents).toContain(ev);
    }
    expect(outcome.txHashes.length).toBeGreaterThanOrEqual(2);
  }

  // Test 3 — missing event at execute fails verify()
  {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = suite.factory();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    const advanceSecs = suite.delayAdvance ?? BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60);
    const originalSchedule = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (args) => {
      const result = await originalSchedule(args);
      chain.advanceSeconds(advanceSecs);
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
  }

  // Test 4 — deprecation flag on new entry → REGISTRY_COLLISION
  {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = suite.factory();
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(ceremony.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      slug: ceremony.slug,
    });
    for (const ev of suite.expectedEvents) chain.pendingEvents.push({ eventName: ev });
    const advanceSecs = suite.delayAdvance ?? BigInt(STANDARD_TIMELOCK_DELAY_SECONDS + 60);
    const originalSchedule = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (args) => {
      const result = await originalSchedule(args);
      chain.advanceSeconds(advanceSecs);
      return result;
    };
    const preview = await ceremony.proposal({ context: ctx, chain });
    chain.setDeprecationFlag(`${suite.registryName}:${preview.proposalHash}`, {
      reasonCode: 0x07,
      disclosureCid: "bafy-cid",
    });
    let caught: CeremonyError | undefined;
    try {
      await ceremony.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(caught).toBeInstanceOf(CeremonyError);
    expect(caught!.code).toBe(CeremonyErrorCode.REGISTRY_COLLISION);
  }
}
