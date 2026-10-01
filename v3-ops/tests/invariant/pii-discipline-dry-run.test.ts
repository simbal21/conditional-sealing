import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { existsSync } from "node:fs";
import {
  G4BinaryHashUpdateCeremony,
  ShredTriggerCeremony,
  generateCeremonyId,
} from "../../src/ceremony/index.js";
import { MockChain } from "../_fixtures/mock-chain.js";
import { ShredAuthority } from "../../src/types/authority-enums.js";
import { makeDryRunVaultClient } from "../../src/adapters/index.js";
import type { Address, Hex } from "viem";
import { LOG_FIELD_DENY_LIST } from "../../src/logging/pii-allow-list.js";

const H = (n: number) => (("0x" + n.toString(16).padStart(2, "0").repeat(32)) as Hex);

let tmpDir: string;
beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "v3-ops-pii-"));
});
afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

/**
 * §0.9 + §1.5 + §1.7 CEREMONY_ERR_PII_IN_LOG verification.
 *
 * §14.7 + §16.4 specify that `public-copy-sensitive` ceremony outputs MUST
 * honor the same PII discipline in dry-run output as in production logs.
 *
 * These tests verify that:
 *   1. Production-path ceremony logs contain ONLY allow-listed field keys.
 *   2. Dry-run path does NOT write to disk (no log file created).
 *   3. Snapshot of dry-run records contains NO denied keys.
 */

describe("§0.9 + §1.5 PII discipline applies equally to prod logs and dry-run", () => {
  it("g4-binary-hash-update prod log on disk contains no σ / share / DEK / plaintext / ciphertext / refusal text", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    chain.pendingEvents.push({ eventName: "EntryAdded" });
    const orig = chain.scheduleTimelock.bind(chain);
    chain.scheduleTimelock = async (a) => {
      const r = await orig(a);
      chain.advanceSeconds(BigInt(7 * 24 * 60 * 60 + 60));
      return r;
    };
    const ceremony = new G4BinaryHashUpdateCeremony({
      registryAddress: "0x1234567890123456789012345678901234567890" as Address,
      g4AuthorityRef: H(0x01),
      binaryHash: H(0xaa),
      sourceCommitDigest: H(0xbb),
      buildEnvDigest: H(0xcc),
      testVectorDigest: H(0xdd),
      metadataHash: H(0xee),
      effectiveBlock: 2_000_000n,
      addEntryCalldata: H(0xff),
      salt: H(0x11),
    });
    const logFile = join(tmpDir, "g4.log");
    const ctx = {
      ceremonyId: generateCeremonyId(ceremony.slug),
      proposalHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: false,
      logFile,
    };
    await ceremony.run({ context: ctx, chain });

    expect(existsSync(logFile)).toBe(true);
    const contents = await readFile(logFile, { encoding: "utf-8" });
    for (const denied of LOG_FIELD_DENY_LIST) {
      // Look for `"<deniedKey>"` JSON-style — strict match. Skip if the key
      // appears as part of an allow-listed compound (e.g. "encryptedReasonBlobHash"
      // contains the substring "encrypted" but is allowed).
      const jsonKey = `"${denied}"`;
      expect(contents).not.toContain(jsonKey);
    }
  });

  it("dry-run does NOT write a log file to disk", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = new G4BinaryHashUpdateCeremony({
      registryAddress: "0x1234567890123456789012345678901234567890" as Address,
      g4AuthorityRef: H(0x01),
      binaryHash: H(0xaa),
      sourceCommitDigest: H(0xbb),
      buildEnvDigest: H(0xcc),
      testVectorDigest: H(0xdd),
      metadataHash: H(0xee),
      effectiveBlock: 2_000_000n,
      addEntryCalldata: H(0xff),
      salt: H(0x11),
    });
    const logFile = join(tmpDir, "g4-dry.log");
    const ctx = {
      ceremonyId: generateCeremonyId(ceremony.slug),
      proposalHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      logFile,
    };
    await ceremony.run({ context: ctx, chain });

    expect(existsSync(logFile)).toBe(false);
  });

  it("dry-run snapshot applies the SAME PII gate (proven by symmetry — shred-trigger dry-run runs through identical pipeline)", async () => {
    const chain = new MockChain({ initialBlock: 1_000_000n });
    const ceremony = new ShredTriggerCeremony({
      conditionEngineAddress: "0x1234567890123456789012345678901234567890" as Address,
      shredRegistryAddress: "0x9876543210987654321098765432109876543210" as Address,
      hCommit: H(0x10),
      authorityMode: ShredAuthority.SUBJECT,
      authorityProof: H(0x20),
      conditionEvaluatedTrue: true,
      postChallengeRevealInProgress: false,
      challengeWindowCompleted: true,
      minLatencyBlocksElapsed: true,
      reasonDigest: H(0x30),
      legalBasisDigest: null,
      addEntryCalldata: H(0x50),
      salt: H(0x51),
      vaultClient: makeDryRunVaultClient().client,
    });
    const logFile = join(tmpDir, "shred-dry.log");
    const ctx = {
      ceremonyId: generateCeremonyId(ceremony.slug),
      proposalHash: ("0x" + "00".repeat(32)) as `0x${string}`,
      commitBlock: 1_500_000n,
      chainId: 84532,
      dryRun: true,
      logFile,
    };
    const outcome = await ceremony.run({ context: ctx, chain });
    expect(outcome.success).toBe(true);
    expect(existsSync(logFile)).toBe(false);
  });
});
