// Foundation test — SDK independence per §9.5 NORMATIVE.
//
// Asserts:
//   - SDK package.json has ZERO workspace deps on Cealis runtime packages
//   - SDK source MUST NOT import from @cealis/v3-*
//   - SDK source MUST NOT import from any HTTP client (axios/node-fetch/got/undici)

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SDK_ROOT = resolve(__dirname, "..", "..");
const PKG_PATH = resolve(SDK_ROOT, "package.json");
const SRC_DIR = resolve(SDK_ROOT, "src");

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

describe("§9.5 SDK independence", () => {
  it("SDK package.json has NO @cealis/* workspace deps", () => {
    const pkg = JSON.parse(readFileSync(PKG_PATH, "utf-8"));
    const all = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
      ...(pkg.peerDependencies ?? {}),
    };
    for (const name of Object.keys(all)) {
      expect(name).not.toMatch(/^@cealis\//);
    }
  });

  it("SDK package.json has NO HTTP client deps (axios/node-fetch/got/undici)", () => {
    const pkg = JSON.parse(readFileSync(PKG_PATH, "utf-8"));
    const all = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
      ...(pkg.peerDependencies ?? {}),
    };
    const forbidden = ["axios", "node-fetch", "got", "undici"];
    for (const f of forbidden) {
      expect(Object.keys(all)).not.toContain(f);
    }
  });

  it("SDK source MUST NOT import from @cealis/* OR HTTP clients", () => {
    const files = collectTs(SRC_DIR);
    const forbidden = [
      /from\s+["']@cealis\//,
      /from\s+["']axios["']/,
      /from\s+["']node-fetch["']/,
      /from\s+["']got["']/,
      /from\s+["']undici["']/,
    ];
    const violations: Array<{ file: string; line: string }> = [];
    for (const file of files) {
      const content = readFileSync(file, "utf-8");
      for (const [idx, line] of content.split("\n").entries()) {
        const trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) continue;
        for (const pat of forbidden) {
          if (pat.test(line)) {
            violations.push({ file, line: `L${idx + 1}: ${line}` });
          }
        }
      }
    }
    expect(violations).toEqual([]);
  });
});
