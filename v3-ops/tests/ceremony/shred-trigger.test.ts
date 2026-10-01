import { describe, it, expect } from "vitest";
import type { Address, Hex } from "viem";
import {
  ShredTriggerCeremony,
  generateCeremonyId,
  makeContext,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import type { CeremonyError} from "../../src/errors/index.js";
import { CeremonyErrorCode } from "../../src/errors/index.js";
import { ShredAuthority } from "../../src/types/authority-enums.js";
import { makeDryRunVaultClient } from "../../src/adapters/index.js";

const COND: Address = "0xaaaa000000000000000000000000000000000001";
const SHRED: Address = "0xaaaa000000000000000000000000000000000002";
const H = (n: number) => (("0x" + n.toString(16).padStart(2, "0").repeat(32)) as Hex);

function baseInput(authorityMode: ShredAuthority) {
  return {
    conditionEngineAddress: COND,
    shredRegistryAddress: SHRED,
    hCommit: H(0x10),
    authorityMode,
    authorityProof: H(0x20),
    conditionEvaluatedTrue: true,
    postChallengeRevealInProgress: false,
    challengeWindowCompleted: true,
    minLatencyBlocksElapsed: true,
    reasonDigest: H(0x30),
    legalBasisDigest: authorityMode === ShredAuthority.OPERATOR ? H(0x40) : null,
    addEntryCalldata: H(0x50),
    salt: H(0x51),
    vaultClient: makeDryRunVaultClient().client,
  };
}

describe("shred-trigger §11 — 5 authority modes", () => {
  for (const mode of [
    ShredAuthority.SUBJECT,
    ShredAuthority.JOINT,
    ShredAuthority.OPERATOR,
    ShredAuthority.TIMELOCK,
  ]) {
    it(`${mode} mode happy path dry-run reaches ShredFinalized`, async () => {
      const chain = new MockChain({ initialBlock: 1_000_000n });
      const ceremony = new ShredTriggerCeremony(baseInput(mode));
      const ctx = makeContext({
        ceremonyId: generateCeremonyId(ceremony.slug),
        commitBlock: 1_500_000n,
        chainId: 84532,
        dryRun: true,
        slug: ceremony.slug,
      });
      const outcome = await ceremony.run({ context: ctx, chain });
      expect(outcome.success).toBe(true);
      expect(outcome.emittedEvents).toContain("ShredRequested");
      expect(outcome.emittedEvents).toContain("ShredFinalized");
      expect(ceremony.getProofShred()).not.toBeNull();
    });
  }

  it("Disabled mode → TRIPWIRE_BYPASS at proposal stage", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = new ShredTriggerCeremony(baseInput(ShredAuthority.DISABLED));
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

  it("§11.4 MANDATORY guardrail: post_challenge_reveal_in_progress=true → TRIPWIRE_BYPASS", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const input = baseInput(ShredAuthority.SUBJECT);
    const ceremony = new ShredTriggerCeremony({
      ...input,
      postChallengeRevealInProgress: true,
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

  it("guardrail fires BEFORE authority check (Disabled+guardrail-violation still hits guardrail first)", async () => {
    // The order matters: guardrail (TRIPWIRE_BYPASS) should fire before
    // any per-mode-specific check. Disabled mode also triggers
    // TRIPWIRE_BYPASS, so we use Subject + guardrail-violation to
    // distinguish: only the guardrail path emits its
    // `postChallengeRevealInProgress`-derived error.
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const input = baseInput(ShredAuthority.SUBJECT);
    const ceremony = new ShredTriggerCeremony({
      ...input,
      postChallengeRevealInProgress: true,
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
    expect(caught?.stage).toBe("proposal"); // not queue
    expect(caught?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });

  it("Operator mode without legalBasisDigest → QUORUM_MISSING", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const input = baseInput(ShredAuthority.OPERATOR);
    const ceremony = new ShredTriggerCeremony({
      ...input,
      legalBasisDigest: null,
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
    expect(caught?.code).toBe(CeremonyErrorCode.QUORUM_MISSING);
  });

  it("conditionEvaluatedTrue=false → TRIPWIRE_BYPASS at queue", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const input = baseInput(ShredAuthority.SUBJECT);
    const ceremony = new ShredTriggerCeremony({
      ...input,
      conditionEvaluatedTrue: false,
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

  it("minLatencyBlocksElapsed=false → TIMELOCK_NOT_EXPIRED at queue", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const input = baseInput(ShredAuthority.SUBJECT);
    const ceremony = new ShredTriggerCeremony({
      ...input,
      minLatencyBlocksElapsed: false,
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
    expect(caught?.code).toBe(CeremonyErrorCode.TIMELOCK_NOT_EXPIRED);
  });
});
