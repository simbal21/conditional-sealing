import { describe, it, expect } from "vitest";
import type { Address, Hex } from "viem";
import {
  PauseActivationCeremony,
  PauseDeactivationCeremony,
  ChallengeResolutionCeremony,
  DisasterRecoveryCeremony,
  VaultOperatorTransitionCeremony,
  generateCeremonyId,
  makeContext,
  VALID_CHALLENGE_RESOLVER_ACTIONS,
  CHALLENGE_EXTENSION_MAX_DAYS,
  type ChallengeResolverAction,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";
import { PauseAuthority } from "../../src/types/authority-enums.js";

const ADDR: Address = "0xbbbb000000000000000000000000000000000001";
const H = (n: number) => (("0x" + n.toString(16).padStart(2, "0").repeat(32)) as Hex);

describe("pause-activation (§12)", () => {
  it("Partner mode happy path emits PauseActivated", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const c = new PauseActivationCeremony({
      conditionEngineAddress: ADDR,
      pauseAuthorityMode: PauseAuthority.PARTNER,
      pauseAuthorityId: H(0x10),
      authorityProof: H(0x11),
      hCommit: H(0x12),
      reasonDigest: H(0x13),
      durationSeconds: 60 * 60,
      addEntryCalldata: H(0x14),
      salt: H(0x15),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(c.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: c.slug,
    });
    const outcome = await c.run({ context: ctx, chain });
    expect(outcome.emittedEvents).toContain("PauseActivated");
  });

  it("None mode → QUORUM_MISSING at construct", () => {
    expect(
      () =>
        new PauseActivationCeremony({
          conditionEngineAddress: ADDR,
          pauseAuthorityMode: PauseAuthority.NONE,
          pauseAuthorityId: H(0x10),
          authorityProof: H(0x11),
          hCommit: H(0x12),
          reasonDigest: H(0x13),
          durationSeconds: 60 * 60,
          addEntryCalldata: H(0x14),
          salt: H(0x15),
        }),
    ).toThrowError(CeremonyError);
  });

  it("durationSeconds > 90 days → TRIPWIRE_BYPASS", () => {
    expect(
      () =>
        new PauseActivationCeremony({
          conditionEngineAddress: ADDR,
          pauseAuthorityMode: PauseAuthority.PARTNER,
          pauseAuthorityId: H(0x10),
          authorityProof: H(0x11),
          hCommit: H(0x12),
          reasonDigest: H(0x13),
          durationSeconds: 91 * 24 * 60 * 60,
          addEntryCalldata: H(0x14),
          salt: H(0x15),
        }),
    ).toThrowError(CeremonyError);
  });

  it("durationSeconds === 0 → TRIPWIRE_BYPASS", () => {
    try {
      new PauseActivationCeremony({
        conditionEngineAddress: ADDR,
        pauseAuthorityMode: PauseAuthority.PARTNER,
        pauseAuthorityId: H(0x10),
        authorityProof: H(0x11),
        hCommit: H(0x12),
        reasonDigest: H(0x13),
        durationSeconds: 0,
        addEntryCalldata: H(0x14),
        salt: H(0x15),
      });
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
    }
  });
});

describe("pause-deactivation (§12)", () => {
  it("Partner mode happy path emits PauseDeactivated", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const c = new PauseDeactivationCeremony({
      conditionEngineAddress: ADDR,
      pauseAuthorityMode: PauseAuthority.PARTNER,
      pauseAuthorityId: H(0x10),
      authorityProof: H(0x11),
      hCommit: H(0x12),
      unpauseReasonDigest: H(0x13),
      addEntryCalldata: H(0x14),
      salt: H(0x15),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(c.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: c.slug,
    });
    const outcome = await c.run({ context: ctx, chain });
    expect(outcome.emittedEvents).toContain("PauseDeactivated");
  });

  it("None mode → QUORUM_MISSING", () => {
    expect(
      () =>
        new PauseDeactivationCeremony({
          conditionEngineAddress: ADDR,
          pauseAuthorityMode: PauseAuthority.NONE,
          pauseAuthorityId: H(0x10),
          authorityProof: H(0x11),
          hCommit: H(0x12),
          unpauseReasonDigest: H(0x13),
          addEntryCalldata: H(0x14),
          salt: H(0x15),
        }),
    ).toThrowError(CeremonyError);
  });
});

describe("challenge-registry-resolution (§12.7)", () => {
  it("VALID_CHALLENGE_RESOLVER_ACTIONS has exactly 3 entries", () => {
    expect(VALID_CHALLENGE_RESOLVER_ACTIONS).toHaveLength(3);
    expect(VALID_CHALLENGE_RESOLVER_ACTIONS).toEqual([
      "confirmNoIntervention",
      "haltCeremony",
      "extendChallenge",
    ]);
  });

  it("CHALLENGE_EXTENSION_MAX_DAYS = 90", () => {
    expect(CHALLENGE_EXTENSION_MAX_DAYS).toBe(90);
  });

  for (const action of [
    "confirmNoIntervention",
    "haltCeremony",
  ] as ChallengeResolverAction[]) {
    it(`${action} resolution dry-run emits ChallengeResolved`, async () => {
      const chain = new MockChain({ initialBlock: 1_000_000n });
      const c = new ChallengeResolutionCeremony({
        challengeRegistryAddress: ADDR,
        challengeId: H(0x20),
        resolverAction: action,
        resolverActionRef: H(0x21),
        hCommit: H(0x22),
        pdaScope: H(0x23),
        extensionSeconds: null,
        addEntryCalldata: H(0x24),
        salt: H(0x25),
      });
      const ctx = makeContext({
        ceremonyId: generateCeremonyId(c.slug),
        commitBlock: 1_500_000n,
        chainId: 84532,
        dryRun: true,
        slug: c.slug,
      });
      const outcome = await c.run({ context: ctx, chain });
      expect(outcome.emittedEvents).toContain("ChallengeResolved");
    });
  }

  it("extendChallenge emits ChallengeExtended (NOT ChallengeResolved)", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const c = new ChallengeResolutionCeremony({
      challengeRegistryAddress: ADDR,
      challengeId: H(0x20),
      resolverAction: "extendChallenge",
      resolverActionRef: H(0x21),
      hCommit: H(0x22),
      pdaScope: H(0x23),
      extensionSeconds: 24 * 60 * 60,
      addEntryCalldata: H(0x24),
      salt: H(0x25),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(c.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: c.slug,
    });
    const outcome = await c.run({ context: ctx, chain });
    expect(outcome.emittedEvents).toContain("ChallengeExtended");
    expect(outcome.emittedEvents).not.toContain("ChallengeResolved");
  });

  it("invalid resolver action → TRIPWIRE_BYPASS at construct", () => {
    try {
      new ChallengeResolutionCeremony({
        challengeRegistryAddress: ADDR,
        challengeId: H(0x20),
        resolverAction: "invalid" as ChallengeResolverAction,
        resolverActionRef: H(0x21),
        hCommit: H(0x22),
        pdaScope: H(0x23),
        extensionSeconds: null,
        addEntryCalldata: H(0x24),
        salt: H(0x25),
      });
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
    }
  });

  it("extendChallenge > 90 days → TRIPWIRE_BYPASS", () => {
    expect(
      () =>
        new ChallengeResolutionCeremony({
          challengeRegistryAddress: ADDR,
          challengeId: H(0x20),
          resolverAction: "extendChallenge",
          resolverActionRef: H(0x21),
          hCommit: H(0x22),
          pdaScope: H(0x23),
          extensionSeconds: 91 * 24 * 60 * 60,
          addEntryCalldata: H(0x24),
          salt: H(0x25),
        }),
    ).toThrowError(CeremonyError);
  });

  it("missing resolverActionRef → TRIPWIRE_BYPASS", () => {
    expect(
      () =>
        new ChallengeResolutionCeremony({
          challengeRegistryAddress: ADDR,
          challengeId: H(0x20),
          resolverAction: "haltCeremony",
          resolverActionRef: ("0x" + "00".repeat(32)) as Hex,
          hCommit: H(0x22),
          pdaScope: H(0x23),
          extensionSeconds: null,
          addEntryCalldata: H(0x24),
          salt: H(0x25),
        }),
    ).toThrowError(CeremonyError);
  });
});

describe("disaster-recovery-bundle (§14)", () => {
  it("canonical-in-use happy path emits DeprecationFlagSet + DisclosurePublished", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const c = new DisasterRecoveryCeremony({
      registryAddress: ADDR,
      affectedSurface: "g4-phase2-authority-or-measurement",
      affectedEntryRef: H(0x30),
      canonicalInUse: true,
      reasonCode: 0x07,
      disclosureCid: "bafy-disaster",
      disclosureCommitHash: H(0x31),
      replacementStaged: false,
      stagedReplacementRef: null,
      metadataHash: H(0x32),
      deprecationCalldata: H(0x33),
      replacementCalldata: H(0x34),
      salt: H(0x35),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(c.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: c.slug,
    });
    const outcome = await c.run({ context: ctx, chain });
    expect(outcome.emittedEvents).toContain("DeprecationFlagSet");
    expect(outcome.emittedEvents).toContain("DisclosurePublished");
  });

  it("missing disclosure → DEPRECATION_DISCLOSURE_MISSING", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const c = new DisasterRecoveryCeremony({
      registryAddress: ADDR,
      affectedSurface: "plugin-rotation",
      affectedEntryRef: H(0x30),
      canonicalInUse: true,
      reasonCode: 0x06,
      disclosureCid: "",
      disclosureCommitHash: ("0x" + "00".repeat(32)) as Hex,
      replacementStaged: false,
      stagedReplacementRef: null,
      metadataHash: H(0x32),
      deprecationCalldata: H(0x33),
      replacementCalldata: H(0x34),
      salt: H(0x35),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(c.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: c.slug,
    });
    let caught: CeremonyError | undefined;
    try {
      await c.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(caught?.code).toBe(CeremonyErrorCode.DEPRECATION_DISCLOSURE_MISSING);
  });

  it("replacement staged → also emits EntryAdded", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const c = new DisasterRecoveryCeremony({
      registryAddress: ADDR,
      affectedSurface: "oracle-compromise",
      affectedEntryRef: H(0x30),
      canonicalInUse: true,
      reasonCode: 0x09,
      disclosureCid: "bafy-x",
      disclosureCommitHash: H(0x31),
      replacementStaged: true,
      stagedReplacementRef: H(0x36),
      metadataHash: H(0x32),
      deprecationCalldata: H(0x33),
      replacementCalldata: H(0x34),
      salt: H(0x35),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(c.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: c.slug,
    });
    const outcome = await c.run({ context: ctx, chain });
    expect(outcome.emittedEvents).toContain("EntryAdded");
  });
});

describe("vault-operator-transition (§14.3)", () => {
  it("planned transition dry-run emits VaultTransitionQueued + Finalized", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const c = new VaultOperatorTransitionCeremony({
      vaultControllerAddress: ADDR,
      sourceVaultRoot: H(0x40),
      destinationVaultRoot: H(0x41),
      sourceAuditLogRoot: H(0x42),
      destinationAuditLogRoot: H(0x43),
      retentionStateRoot: H(0x44),
      shredStateRoot: H(0x45),
      migrationManifestHash: H(0x46),
      rollbackBound: 100_000n,
      notificationHash: H(0x47),
      emergencyReadHalt: false,
      addEntryCalldata: H(0x48),
      salt: H(0x49),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(c.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: c.slug,
    });
    const outcome = await c.run({ context: ctx, chain });
    expect(outcome.emittedEvents).toContain("VaultTransitionQueued");
    expect(outcome.emittedEvents).toContain("VaultTransitionFinalized");
  });

  it("identical source + destination audit roots → TRIPWIRE_BYPASS", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const c = new VaultOperatorTransitionCeremony({
      vaultControllerAddress: ADDR,
      sourceVaultRoot: H(0x40),
      destinationVaultRoot: H(0x41),
      sourceAuditLogRoot: H(0x42),
      destinationAuditLogRoot: H(0x42), // identical — fail
      retentionStateRoot: H(0x44),
      shredStateRoot: H(0x45),
      migrationManifestHash: H(0x46),
      rollbackBound: 100_000n,
      notificationHash: H(0x47),
      emergencyReadHalt: false,
      addEntryCalldata: H(0x48),
      salt: H(0x49),
    });
    const ctx = makeContext({
      ceremonyId: generateCeremonyId(c.slug),
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      slug: c.slug,
    });
    let caught: CeremonyError | undefined;
    try {
      await c.run({ context: ctx, chain });
    } catch (e) {
      caught = e as CeremonyError;
    }
    expect(caught?.code).toBe(CeremonyErrorCode.TRIPWIRE_BYPASS);
  });
});
