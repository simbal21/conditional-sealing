// Foundation test — §15 one-way edge barrier.
//
// Asserts that no SD source file imports from forbidden @cealis/v3-crypto
// surfaces. Pure grep test against the source tree.
//
// Forbidden surfaces (per §1.5 + §15 NORMATIVE):
//   - shamir          (file_key splitting / combining)
//   - aead            (AEAD encrypt/decrypt of payload)
//   - dek-derivation  (DEK construction from σ values)
//   - reveal-authorized (RevealAuthorized event emission helpers)
//   - sigma-lit / sigma-g3 / sigma-g4 / sigma-subject (gate signing)
//   - hybrid-wrap     (PQ stanza wrap)
//   - stanza-mac      (stanza MAC computation)
//
// This barrier is enforced by:
//   1. m1-imports.ts re-exports a NARROW subset (TS compile-time)
//   2. This grep test (runtime-validated)
//   3. Phase F tripwire grep (CI-validated)

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SRC_DIR = resolve(__dirname, "..", "..", "src");
const SDK_SRC_DIR = resolve(__dirname, "..", "..", "sdk", "src");

const FORBIDDEN_IMPORT_PATTERNS = [
  /from\s+["']@cealis\/v3-crypto\/shamir/,
  /from\s+["']@cealis\/v3-crypto\/aead/,
  /from\s+["']@cealis\/v3-crypto\/dek-derivation/,
  /from\s+["']@cealis\/v3-crypto\/dek/,
  /from\s+["']@cealis\/v3-crypto\/reveal-authorized/,
  /from\s+["']@cealis\/v3-crypto\/sigma/,
  /from\s+["']@cealis\/v3-crypto\/hybrid-wrap/,
  /from\s+["']@cealis\/v3-crypto\/stanza-mac/,
  /from\s+["']@cealis\/v3-crypto\/envelope/,
];

/** Recursively collect all .ts files (excluding node_modules + dist). */
function collectTs(root: string): string[] {
  const out: string[] = [];
  let s;
  try {
    s = statSync(root);
  } catch {
    return out;
  }
  if (!s.isDirectory()) return out;
  for (const entry of readdirSync(root)) {
    if (entry === "node_modules" || entry === "dist" || entry === "coverage") continue;
    const sub = join(root, entry);
    const subStat = statSync(sub);
    if (subStat.isDirectory()) {
      out.push(...collectTs(sub));
    } else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) {
      out.push(sub);
    }
  }
  return out;
}

describe("§15 one-way edge — forbidden-import barrier", () => {
  it("no SD source file imports from @cealis/v3-crypto/{shamir,aead,dek,reveal-authorized,sigma-*,hybrid-wrap,stanza-mac,envelope}", () => {
    const files = [...collectTs(SRC_DIR), ...collectTs(SDK_SRC_DIR)];
    const violations: Array<{ file: string; pattern: string; line: string }> = [];

    for (const file of files) {
      // m1-imports.ts is allowed to discuss these in COMMENTS but never actually import them.
      // The check uses regex against `from "..."` statements only — comments containing the
      // forbidden surface names are fine.
      const content = readFileSync(file, "utf-8");
      const lines = content.split("\n");
      for (const [idx, line] of lines.entries()) {
        // Skip comment lines for the m1-imports facade (it documents the forbidden surfaces).
        const trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;

        for (const pattern of FORBIDDEN_IMPORT_PATTERNS) {
          if (pattern.test(line)) {
            violations.push({ file, pattern: pattern.toString(), line: `L${idx + 1}: ${line}` });
          }
        }
      }
    }

    if (violations.length > 0) {
      console.error("ONE_WAY_EDGE_VIOLATION:", JSON.stringify(violations, null, 2));
    }
    expect(violations).toEqual([]);
  });

  it("m1-imports.ts re-exports a narrow subset (NOT `export *`)", () => {
    const facadePath = resolve(SRC_DIR, "m1-imports.ts");
    const content = readFileSync(facadePath, "utf-8");
    // The facade MUST NOT contain `export * from "@cealis/v3-crypto"`.
    expect(content).not.toMatch(/^export\s+\*\s+from\s+["']@cealis\/v3-crypto["'];?$/m);
  });
});
