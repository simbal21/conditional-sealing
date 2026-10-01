import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// σ-as-AUTHORIZATION discipline test (PHASE-PLAN §0 drift #3).
//
// HKDF-over-σ is the SUPERSEDED σ-as-IKM framing — locked retired 2026-05-05
// per internal design record dek-lifecycle.md. M8 demo MUST NOT
// reintroduce any HKDF(σ) surface in src/. The check is grep over src/
// excluding comment lines, with allow-list for didactic prose mentions
// (e.g. "NO HKDF over σ values anywhere").
//
// Patterns flagged as REGRESSION (case-insensitive substring match in
// non-comment-only lines):
//   - "HKDF(σ"
//   - "hkdf(sigma"
//   - "σ as IKM"
//   - "sigma-as-IKM"
//   - "sigma_as_ikm"
//   - any pattern matching /hkdf.*sigma|sigma.*ikm/i in code (non-comment)

const HERE = fileURLToPath(new URL(".", import.meta.url));
const SRC_DIR = resolve(HERE, "..", "..", "src");

function listTsFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const s = statSync(full);
    if (s.isDirectory()) results.push(...listTsFiles(full));
    else if (s.isFile() && entry.endsWith(".ts")) results.push(full);
  }
  return results;
}

const FILES = listTsFiles(SRC_DIR);

const VIOLATION_PATTERNS: readonly RegExp[] = [
  /hkdf\s*\(\s*sigma/i,
  /hkdf\s*\(\s*σ/i,
  /sigma[-_\s]+as[-_\s]+ikm/i,
  /σ[-_\s]+as[-_\s]+ikm/i,
  /\bikm\s*=\s*sigma/i,
  /\bikm\s*=\s*σ/i,
];

function isCommentOnly(line: string): boolean {
  const trimmed = line.trim();
  return trimmed === "" || trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*");
}

describe("σ-as-authorization discipline (no HKDF-over-σ regression)", () => {
  it("locates v3-demo src/ files", () => {
    expect(FILES.length).toBeGreaterThan(0);
  });

  it("no code-level HKDF(σ) / σ-as-IKM pattern in src/", () => {
    const violations: string[] = [];
    for (const file of FILES) {
      const lines = readFileSync(file, "utf8").split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        if (isCommentOnly(line)) continue;
        for (const pattern of VIOLATION_PATTERNS) {
          if (pattern.test(line)) {
            violations.push(`${file}:${i + 1}: ${line.trim()}`);
          }
        }
      }
    }
    expect(violations).toEqual([]);
  });
});
