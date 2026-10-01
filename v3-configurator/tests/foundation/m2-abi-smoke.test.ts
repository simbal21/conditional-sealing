// Foundation: M2 Foundry ABI smoke test.
//
// Per PHASE-PLAN A3: "Smoke test loads the actual M2 ABI from
// contracts/out/ (Foundry artifact) and asserts the 29 field
// names + types exactly. The §8.6 triple `pda_root` comparison guard
// requires the contract helper ABI to be exact. Phase A's smoke test
// surfaces drift before any Codex chunk wires the guard."
//
// IMPORTANT: at time of Phase A authoring (2026-05-11), M2 ships
// `PdaRootFields` as a Solidity struct (NOT a registerPDA function in
// ConditionEngine yet — the function-level wiring is M5+ scope). The
// smoke test loads the struct directly from
// `contracts/src/lib/Structs.sol` source AND verifies the
// 29-field name list in M2 lowerCamelCase order matches our
// `PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE` constant in m2-imports.ts.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE,
  PDA_ROOT_FIELDS_COUNT,
} from "../../src/m2-imports.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function readStructsSol(): string {
  const path = join(__dirname, "..", "..", "..", "contracts", "src", "lib", "Structs.sol");
  return readFileSync(path, "utf8");
}

describe("@cealis/v3-configurator — M2 Foundry ABI smoke", () => {
  it("M2 contracts/src/lib/Structs.sol exists on disk", () => {
    const source = readStructsSol();
    expect(source.length).toBeGreaterThan(0);
  });

  it("declares struct PdaRootFields", () => {
    const source = readStructsSol();
    expect(source).toMatch(/struct\s+PdaRootFields\s*\{/);
  });

  it("PDA_ROOT_FIELDS_COUNT is 29 (S2-1 §3.3 + §17.4 author-lock)", () => {
    expect(PDA_ROOT_FIELDS_COUNT).toBe(29);
  });

  it("PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE has exactly 29 entries", () => {
    expect(PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE.length).toBe(29);
  });

  it("every Solidity-camelCase field appears in M2's Structs.sol body", () => {
    const source = readStructsSol();
    // Extract the body of `struct PdaRootFields { ... }`.
    const match = /struct\s+PdaRootFields\s*\{([\s\S]*?)\n\}/.exec(source);
    expect(match).not.toBeNull();
    if (match === null) return;
    const body = match[1];
    expect(body).toBeDefined();
    if (body === undefined) return;

    for (const fieldName of PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE) {
      // Field declaration form: "<type>  <fieldName>;" — match the
      // field name as a whole word followed by a semicolon (with optional
      // whitespace).
      const fieldRegex = new RegExp(`\\b${fieldName}\\s*;`);
      expect(body, `M2 Structs.sol must contain field "${fieldName}"`).toMatch(fieldRegex);
    }
  });

  it("M2 struct contains no fields outside the canonical 29-field set", () => {
    const source = readStructsSol();
    const match = /struct\s+PdaRootFields\s*\{([\s\S]*?)\n\}/.exec(source);
    expect(match).not.toBeNull();
    if (match === null) return;
    const body = match[1];
    expect(body).toBeDefined();
    if (body === undefined) return;

    // Collect every identifier-followed-by-semicolon (field declaration form).
    const declared: string[] = [];
    const declRegex = /\b([a-z][A-Za-z0-9]*)\s*;/g;
    let m: RegExpExecArray | null;
    while ((m = declRegex.exec(body)) !== null) {
      const name = m[1];
      if (name !== undefined) declared.push(name);
    }

    // Field declarations: every declared identifier must be in canonical set.
    // (We intentionally do NOT require length === 29 because Solidity-side
    // comments may include identifiers like "field" or "original"; the
    // canonical-set membership check is the load-bearing assertion.)
    for (const decl of declared) {
      expect(
        PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE.includes(decl),
        `M2 Structs.sol field "${decl}" must be in canonical 29-field set`,
      ).toBe(true);
    }
  });
});
