import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

// Source-tree grep: no hard-coded Cealis URLs, no API hostname references.
// Per S2-5 §4.7 — partner-supplied RPC ONLY.

function walk(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, files);
    else if (entry.endsWith(".ts")) files.push(full);
  }
  return files;
}

describe("verify-sdk no-network-deps (source tree)", () => {
  const srcDir = resolve(__dirname, "../../src");
  const files = walk(srcDir);

  it("contains source files (sanity)", () => {
    expect(files.length).toBeGreaterThan(0);
  });

  const FORBIDDEN_STRINGS = [
    "api.cealis",
    "cealis.local",
    "://cealis",
    "cealis-api",
  ];

  it("no Cealis API URL hard-coded in source", () => {
    for (const file of files) {
      const text = readFileSync(file, "utf-8");
      for (const forbidden of FORBIDDEN_STRINGS) {
        expect(
          text.toLowerCase().includes(forbidden),
          `forbidden Cealis URL fragment '${forbidden}' in ${file}`,
        ).toBe(false);
      }
    }
  });

  it("no import of forbidden runtime packages from sibling workspaces", () => {
    for (const file of files) {
      const text = readFileSync(file, "utf-8");
      // Match `from "..."` import specifier
      const matches = text.matchAll(/from\s+['"]([^'"]+)['"]/g);
      for (const m of matches) {
        const spec = m[1];
        if (!spec) continue;
        // Workspace forbidden imports
        expect(spec).not.toBe("@cealis/v3-api");
        expect(spec).not.toBe("@cealis/v3-custody");
        expect(spec.startsWith("axios"), `axios import in ${file}`).toBe(false);
        expect(spec.startsWith("node-fetch"), `node-fetch in ${file}`).toBe(false);
      }
    }
  });
});
