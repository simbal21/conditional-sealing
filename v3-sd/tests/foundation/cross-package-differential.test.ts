// Foundation test A22 — cross-package differential.
//
// Asserts:
//   - @cealis/v3-crypto loads via m1-imports.ts facade
//   - escrow TAG_*_V3 byte32 strings are present + 32-byte hex
//   - M2 ABIs load + every expected function/event present
//   - SDK subpackage is INDEPENDENT (zero workspace deps on Cealis runtime)

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import {
  TAG_COMMIT_V3,
  TAG_AAD_V3,
  TAG_PDA_ROOT_V3,
  TAG_COMMIT_CONTEXT_V3,
  TAG_SUBJECT_V3,
} from "../../src/m1-imports.js";
import {
  loadM2Artifact,
  EXPECTED_DISCLOSURE_REGISTRY_FUNCTIONS,
  EXPECTED_REVOCATION_REGISTRY_FUNCTIONS,
} from "../../src/m2-imports.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SDK_PKG = resolve(__dirname, "..", "..", "sdk", "package.json");

describe("A22 cross-package differential", () => {
  it("M1 facade re-exports load at runtime", () => {
    expect(TAG_COMMIT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(TAG_AAD_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(TAG_PDA_ROOT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(TAG_COMMIT_CONTEXT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(TAG_SUBJECT_V3).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("M2 DisclosureRegistry ABI loads + every expected function is present", () => {
    const artifact = loadM2Artifact("DisclosureRegistry");
    for (const fn of EXPECTED_DISCLOSURE_REGISTRY_FUNCTIONS) {
      const found = artifact.abi.find((i) => i.type === "function" && (i as { name: string }).name === fn);
      expect(found, `expected function ${fn} in DisclosureRegistry ABI`).toBeDefined();
    }
  });

  it("M2 DisclosureRevocationRegistry ABI loads + every expected function is present", () => {
    const artifact = loadM2Artifact("DisclosureRevocationRegistry");
    for (const fn of EXPECTED_REVOCATION_REGISTRY_FUNCTIONS) {
      const found = artifact.abi.find((i) => i.type === "function" && (i as { name: string }).name === fn);
      expect(found, `expected function ${fn} in DisclosureRevocationRegistry ABI`).toBeDefined();
    }
  });

  it("SDK subpackage has zero workspace deps on Cealis runtime packages (§9.5 independence)", () => {
    const pkg = JSON.parse(readFileSync(SDK_PKG, "utf-8"));
    const all = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
      ...(pkg.peerDependencies ?? {}),
    };
    expect(Object.keys(all)).not.toContain("@cealis/v3-crypto");
    expect(Object.keys(all)).not.toContain("@cealis/v3-custody");
    expect(Object.keys(all)).not.toContain("@cealis/v3-api");
    expect(Object.keys(all)).not.toContain("@cealis/v3-configurator");
    expect(Object.keys(all)).not.toContain("@cealis/v3-sd");
    expect(Object.keys(all)).not.toContain("@cealis/verify-sdk");
  });
});
