// Foundation test — App. M wording-lint script smoke.
//
// Asserts:
//   - scripts/wording-lint.mjs is executable
//   - scripts/banned-phrases.json contains §M.2 banned phrasings
//   - script flags a synthetic violation

import { describe, it, expect } from "vitest";
import { statSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { dirname } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCRIPT_PATH = resolve(__dirname, "..", "..", "scripts", "wording-lint.mjs");
const BANNED_PATH = resolve(__dirname, "..", "..", "scripts", "banned-phrases.json");

describe("App. M wording-lint", () => {
  it("scripts/wording-lint.mjs exists", () => {
    expect(statSync(SCRIPT_PATH).isFile()).toBe(true);
  });

  it("scripts/banned-phrases.json contains §M.2 banned phrasings", () => {
    const raw = JSON.parse(readFileSync(BANNED_PATH, "utf-8"));
    expect(Array.isArray(raw.banned_phrases)).toBe(true);
    expect(raw.banned_phrases.length).toBeGreaterThan(5);
    expect(raw.banned_phrases).toContain("SD partially unlocks the escrow");
    expect(raw.banned_phrases).toContain("ZK means the partner learns nothing");
    expect(raw.banned_phrases).toContain("Cleartext SD is private");
    expect(raw.banned_phrases).toContain("Mode B supports the same SD flow");
    expect(raw.banned_phrases).toContain("Revocation deletes partner-held proofs");
  });

  it("wording-lint script flags a synthetic violation", () => {
    const dir = mkdtempSync(join(tmpdir(), "cealis-m6-lint-"));
    try {
      const violationFile = join(dir, "violation.md");
      writeFileSync(violationFile, "This document says: SD partially unlocks the escrow when called.\n");

      let exitCode = 0;
      let out = "";
      try {
        out = execSync(`node "${SCRIPT_PATH}" "${violationFile}"`, { encoding: "utf-8" });
      } catch (err: unknown) {
        const e = err as { status?: number; stdout?: string };
        exitCode = e.status ?? 1;
        out = e.stdout ?? "";
      }

      expect(exitCode).toBe(1);
      const result = JSON.parse(out);
      expect(result.banned_phrase_hits).toBeGreaterThan(0);
      expect(result.findings.some((f: { phrase: string }) => f.phrase === "SD partially unlocks the escrow")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
