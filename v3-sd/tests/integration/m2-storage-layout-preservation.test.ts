import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

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

describe("M2 DisclosureRegistry storage-layout preservation after Phase D", () => {
  it("preserves slots 0..4 and appends verifier mapping before the shrunken gap", () => {
    const baseline = JSON.parse(readFileSync(BASELINE_PATH, "utf-8")) as {
      storage: Array<{ label: string; slot: string; type: string }>;
    };

    expect(baseline.storage.map((entry) => [entry.slot, entry.label])).toEqual([
      ["0", "_roles"],
      ["1", "_pauses"],
      ["2", "_revocationRegistry"],
      ["3", "_disclosureDigests"],
      ["4", "_knownVerifiers"],
      ["5", "_verifierContracts"],
      ["6", "__gap"],
    ]);
    expect(baseline.storage[5]?.type).toContain("t_mapping(t_bytes32,t_address)");
    expect(baseline.storage[6]?.type).toMatch(/49/);
  });
});

