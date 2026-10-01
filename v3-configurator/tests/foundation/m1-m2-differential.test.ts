// Foundation: M1 ↔ M2 ↔ S2-4 differential test (Phase A acceptance gate).
//
// Per PHASE-PLAN A18: "Mirror M2/M3 Phase A pattern: confirm Phase A
// foundations actually wire through to M1 + M2 before any Codex chunk
// fires. If this test fails, M1 or M2 build is stale — STOP, fix, then
// start chunks."
//
// This test asserts the 29-field count + name correspondence across
// THREE layers:
//   1. M1 (@cealis/v3-crypto) — TypeScript PDARootInput interface
//      (verified via zeroPDARootInput() return value's key count).
//   2. M2 (Cealis V3 contracts) — Solidity struct PdaRootFields
//      (verified via reading Structs.sol).
//   3. S2-4 (this package) — PdaRootFields interface in
//      `src/types/pda-root.ts`.
//
// All three layers MUST agree on 29 fields. If M2 ever ships 28, STOP
// per PHASE-PLAN Failure Modes.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { zeroPDARootInput } from "../../src/m1-imports.js";
import {
  PDA_ROOT_FIELDS_COUNT,
  PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE,
} from "../../src/m2-imports.js";
import {
  PDA_ROOT_FIELD_COUNT,
  PDA_ROOT_FIELD_NAMES,
} from "../../src/types/pda-root.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Convert snake_case to lowerCamelCase.
 *
 * Used to bridge M1/S2-4 snake_case ↔ M2 lowerCamelCase names.
 * `subject_authenticator_class` → `subjectAuthenticatorClass`.
 * `art_9_scoped` → `art9Scoped` (digits join without underscore).
 */
function snakeToCamel(snake: string): string {
  return snake.replace(/_([a-z0-9])/g, (_, ch: string) => ch.toUpperCase());
}

describe("@cealis/v3-configurator — M1 ↔ M2 ↔ S2-4 differential (Phase A acceptance gate)", () => {
  it("S2-4 PdaRootFields TS interface has 29 fields", () => {
    expect(PDA_ROOT_FIELD_COUNT).toBe(29);
    expect(PDA_ROOT_FIELD_NAMES.length).toBe(29);
  });

  it("M2 PDA_ROOT_FIELDS_COUNT is 29", () => {
    expect(PDA_ROOT_FIELDS_COUNT).toBe(29);
    expect(PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE.length).toBe(29);
  });

  it("M1 zeroPDARootInput() returns an object with 29 keys", () => {
    const input = zeroPDARootInput();
    const keys = Object.keys(input);
    expect(keys.length).toBe(29);
  });

  it("S2-4 snake_case names map 1:1 to M2 lowerCamelCase names in order", () => {
    for (let i = 0; i < 29; i++) {
      const s2_4_snake = PDA_ROOT_FIELD_NAMES[i];
      const m2_camel = PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE[i];
      expect(s2_4_snake).toBeDefined();
      expect(m2_camel).toBeDefined();
      if (s2_4_snake === undefined || m2_camel === undefined) continue;
      const converted = snakeToCamel(s2_4_snake);
      expect(
        converted,
        `S2-4 field "${s2_4_snake}" at position ${i} converts to "${converted}"; M2 expects "${m2_camel}"`,
      ).toBe(m2_camel);
    }
  });

  it("M1 PDARootInput keys correspond 1:1 to S2-4 PdaRootFields names", () => {
    const input = zeroPDARootInput();
    const m1Keys = new Set(Object.keys(input));
    for (const s2_4Name of PDA_ROOT_FIELD_NAMES) {
      expect(m1Keys.has(s2_4Name), `M1 PDARootInput must have key "${s2_4Name}"`).toBe(true);
    }
  });

  it("M1 PDARootInput contains no fields outside the S2-4 canonical 29-field set", () => {
    const input = zeroPDARootInput();
    const s2_4Set = new Set(PDA_ROOT_FIELD_NAMES);
    for (const key of Object.keys(input)) {
      expect(
        s2_4Set.has(key as (typeof PDA_ROOT_FIELD_NAMES)[number]),
        `M1 PDARootInput key "${key}" must be in S2-4 canonical 29-field set`,
      ).toBe(true);
    }
  });

  it("M2 Structs.sol body contains every M2 canonical field name verbatim", () => {
    const structsPath = join(
      __dirname,
      "..",
      "..",
      "..",
      "contracts",
      "src",
      "lib",
      "Structs.sol",
    );
    const source = readFileSync(structsPath, "utf8");
    const match = /struct\s+PdaRootFields\s*\{([\s\S]*?)\n\}/.exec(source);
    expect(match).not.toBeNull();
    if (match === null) return;
    const body = match[1];
    expect(body).toBeDefined();
    if (body === undefined) return;
    for (const m2Field of PDA_ROOT_FIELDS_SOLIDITY_CAMEL_CASE) {
      expect(body).toMatch(new RegExp(`\\b${m2Field}\\s*;`));
    }
  });
});
