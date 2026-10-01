// Foundation test — M2 storage-layout baseline integrity.
//
// SOFT-2 choice (a): baseline snapshot at
//   contracts/test/disclosure/DisclosureRegistry.storage-layout.baseline.json
// is checked in PRE-edit. Phase D updates baseline atomically with the surgical
// edit; Phase F asserts Phase D's edit preserves slot 0..4 verbatim.
//
// Phase D baseline shape:
//   slot 0 _roles, slot 1 _pauses, slot 2 _revocationRegistry,
//   slot 3 _disclosureDigests, slot 4 _knownVerifiers,
//   slot 5 _verifierContracts, slot 6 __gap[49]

import { describe, it, expect } from "vitest";
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const BASELINE_PATH = resolve(
  __dirname,
  "..",
  "..",
  "..",
  "contracts",
  "test",
  "disclosure",
  "DisclosureRegistry.storage-layout.baseline.json",
);

describe("M2 DisclosureRegistry storage-layout baseline (SOFT-2 choice (a))", () => {
  it("baseline JSON file exists at expected path", () => {
    expect(statSync(BASELINE_PATH).isFile()).toBe(true);
  });

  it("baseline contains the expected 7 storage entries in canonical order", () => {
    const baseline = JSON.parse(readFileSync(BASELINE_PATH, "utf-8"));
    expect(Array.isArray(baseline.storage)).toBe(true);
    expect(baseline.storage.length).toBe(7);

    // Verify labels + slots in canonical order — Phase D MUST preserve these.
    const expectedSlots: ReadonlyArray<{ slot: string; label: string }> = [
      { slot: "0", label: "_roles" },
      { slot: "1", label: "_pauses" },
      { slot: "2", label: "_revocationRegistry" },
      { slot: "3", label: "_disclosureDigests" },
      { slot: "4", label: "_knownVerifiers" },
      { slot: "5", label: "_verifierContracts" },
      { slot: "6", label: "__gap" },
    ];

    for (const [idx, expected] of expectedSlots.entries()) {
      const actual = baseline.storage[idx];
      expect(actual.slot).toBe(expected.slot);
      expect(actual.label).toBe(expected.label);
    }
  });

  it("__gap baseline has uint256[49] at slot 6", () => {
    const baseline = JSON.parse(readFileSync(BASELINE_PATH, "utf-8"));
    const gap = baseline.storage[6];
    expect(gap.label).toBe("__gap");
    expect(gap.slot).toBe("6");
    // Foundry storage-layout JSON encodes array element types in
    // internal form `t_array(t_uint256)<N>_storage` rather than Solidity
    // surface `uint256[N]`. Match either form.
    expect(gap.type).toMatch(/uint256/);
    expect(gap.type).toMatch(/49/);
  });
});
