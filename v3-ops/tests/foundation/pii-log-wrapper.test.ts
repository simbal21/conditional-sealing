import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createLogger,
  LOG_FIELD_ALLOW_LIST,
  LOG_FIELD_DENY_LIST,
  isAllowedField,
  isDeniedField,
  isPiiSafeField,
} from "../../src/logging/index.js";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "v3-ops-test-"));
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

/**
 * Drift catch #5 + #10: PII allow-list (positive) + deny-list (belt-and-
 * braces). §0.9 line 69 + §1.5 lines 100–102.
 */
describe("PII allow/deny lists (S2-6 §0.9 + §1.5)", () => {
  it("allow-list contains the §0.9 essentials", () => {
    expect(isAllowedField("ceremonyId")).toBe(true);
    expect(isAllowedField("entryId")).toBe(true);
    expect(isAllowedField("registryName")).toBe(true);
    expect(isAllowedField("roleId")).toBe(true);
    expect(isAllowedField("blockNumber")).toBe(true);
    expect(isAllowedField("disclosureCid")).toBe(true);
    expect(isAllowedField("manifestHash")).toBe(true);
    expect(isAllowedField("encryptedReasonBlobHash")).toBe(true);
  });

  it("deny-list contains all §1.5 banned categories", () => {
    expect(isDeniedField("sigma")).toBe(true);
    expect(isDeniedField("share")).toBe(true);
    expect(isDeniedField("dek")).toBe(true);
    expect(isDeniedField("plaintext")).toBe(true);
    expect(isDeniedField("ciphertext")).toBe(true);
    expect(isDeniedField("oraclePlaintext")).toBe(true);
    expect(isDeniedField("refusalReasonText")).toBe(true);
    expect(isDeniedField("subjectIdentity")).toBe(true);
  });

  it("allow and deny lists do not overlap", () => {
    for (const a of LOG_FIELD_ALLOW_LIST) {
      expect(LOG_FIELD_DENY_LIST).not.toContain(a);
    }
    for (const d of LOG_FIELD_DENY_LIST) {
      expect(LOG_FIELD_ALLOW_LIST).not.toContain(d);
    }
  });

  it("isPiiSafeField only passes allow-listed AND not-denied keys", () => {
    expect(isPiiSafeField("ceremonyId")).toBe(true);
    expect(isPiiSafeField("sigma")).toBe(false);
    expect(isPiiSafeField("nonsense-undefined-key")).toBe(false);
  });
});

describe("createLogger PII gate (prod path)", () => {
  it("emits allowed fields to disk and returns them in snapshot", async () => {
    const logFile = join(tmpDir, "ceremony.log");
    const logger = createLogger({ logFile, dryRun: false });

    await logger.log({
      ceremonyId: "ceremony-001",
      level: "info",
      stage: "proposal",
      message: "queued",
      fields: {
        ceremonyId: "ceremony-001",
        entryId: "0x" + "ab".repeat(32),
        effectiveBlock: 12345n,
      },
    });

    const snap = logger.snapshot();
    expect(snap).toHaveLength(1);
    expect(snap[0]?.message).toBe("queued");

    const onDisk = await readFile(logFile, { encoding: "utf-8" });
    expect(onDisk).toContain("ceremony-001");
    expect(onDisk).toContain("12345"); // bigint serialized as decimal
  });

  it("rejects a forbidden field at log time with PII_IN_LOG", async () => {
    const logFile = join(tmpDir, "ceremony.log");
    const logger = createLogger({ logFile, dryRun: false });

    await expect(
      logger.log({
        ceremonyId: "ceremony-002",
        level: "info",
        stage: "proposal",
        message: "leak attempt",
        fields: {
          ceremonyId: "ceremony-002",
          plaintext: "this should never be logged",
        },
      }),
    ).rejects.toThrowError(CeremonyError);

    try {
      await logger.log({
        ceremonyId: "ceremony-002",
        level: "info",
        stage: "proposal",
        message: "leak attempt",
        fields: { sigma: "deadbeef" },
      });
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.PII_IN_LOG);
    }
  });

  it("rejects a field whose key is neither allowed nor denied (positive allow-list)", async () => {
    const logFile = join(tmpDir, "ceremony.log");
    const logger = createLogger({ logFile, dryRun: false });

    await expect(
      logger.log({
        ceremonyId: "ceremony-003",
        level: "info",
        stage: "proposal",
        message: "unknown field",
        fields: { someRandomKey: "x" },
      }),
    ).rejects.toThrowError(CeremonyError);
  });
});

describe("createLogger dry-run path (S2-6 §14.7 + §16.4)", () => {
  it("dry-run does not write to disk but still records in snapshot", async () => {
    const logFile = join(tmpDir, "ceremony-dry.log");
    const logger = createLogger({ logFile, dryRun: true });

    await logger.log({
      ceremonyId: "ceremony-dry",
      level: "info",
      stage: "proposal",
      message: "dry-run probe",
      fields: { ceremonyId: "ceremony-dry", commitBlock: 100n },
    });

    expect(logger.snapshot()).toHaveLength(1);

    await expect(readFile(logFile, { encoding: "utf-8" })).rejects.toThrow();
  });

  it("dry-run applies the SAME PII gate as production", async () => {
    const logFile = join(tmpDir, "ceremony-dry.log");
    const logger = createLogger({ logFile, dryRun: true });

    await expect(
      logger.log({
        ceremonyId: "ceremony-dry-leak",
        level: "info",
        stage: "proposal",
        message: "dry-run leak attempt",
        fields: { dek: "deadbeef" },
      }),
    ).rejects.toThrowError(CeremonyError);
  });
});
