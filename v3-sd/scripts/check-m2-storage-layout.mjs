#!/usr/bin/env node
// M2 DisclosureRegistry storage-layout regression guard.
//
// PHASE A SOFT-2 choice (a): Foundry-side baseline snapshot at
//   contracts/test/disclosure/DisclosureRegistry.storage-layout.baseline.json
// is checked in PRE-edit. This script shells `forge inspect` for the current
// layout and diffs against the baseline.
//
// Phase D MUST consume + extend this script: the baseline is updated atomically
// in the same commit that introduces the surgical edit (per
// SPEC-COMPLIANCE-GUARD-M6 §22). The assertion at Phase D is that EXISTING
// slots (slot 0..4) are byte-identical to baseline and only `__gap` shrinks
// from 50 → 49 with a single new `_verifierContracts` mapping added BEFORE the
// `__gap` slot.
//
// Phase F runs this script as a gate.

import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const BASELINE_PATH = resolve(__dirname, "..", "..", "contracts", "test", "disclosure",
  "DisclosureRegistry.storage-layout.baseline.json");
const CONTRACTS_DIR = resolve(__dirname, "..", "..", "contracts");
const CONTRACT_REF = "src/disclosure/DisclosureRegistry.sol:DisclosureRegistry";

const baseline = JSON.parse(readFileSync(BASELINE_PATH, "utf-8"));

let current;
try {
  const out = execSync(
    `forge inspect --json ${CONTRACT_REF} storageLayout`,
    {
      cwd: CONTRACTS_DIR,
      encoding: "utf-8",
      env: {
        ...process.env,
        PWD: CONTRACTS_DIR,
        FOUNDRY_CACHE_PATH: process.env.FOUNDRY_CACHE_PATH ?? "/private/tmp/cealis-forge-cache",
      },
    }
  );
  current = JSON.parse(out);
} catch (err) {
  console.error(JSON.stringify({
    error: "forge_inspect_failed",
    detail: String(err),
    hint: "Ensure forge is on PATH and `cd contracts && forge build --extra-output storageLayout` ran first.",
  }, null, 2));
  process.exit(2);
}

// Phase A baseline has 6 storage entries:
//   slot 0 _roles, slot 1 _pauses, slot 2 _revocationRegistry,
//   slot 3 _disclosureDigests, slot 4 _knownVerifiers, slot 5 __gap[50]
//
// Expected Phase D shape:
//   slot 0..4 unchanged (BYTE-IDENTICAL),
//   slot 5 = new `_verifierContracts` mapping(bytes32 => address),
//   slot 6 = __gap[49] (size decremented).
//
// We do NOT enforce a strict shape at Phase A — Phase A just confirms
// baseline matches current state. Phase D updates baseline atomically
// + the assertion narrows.

const sameLayout = JSON.stringify(baseline.storage) === JSON.stringify(current.storage);

const result = {
  contract: CONTRACT_REF,
  baseline_entry_count: baseline.storage.length,
  current_entry_count: current.storage.length,
  matches_baseline: sameLayout,
  baseline_path: BASELINE_PATH,
};

console.log(JSON.stringify(result, null, 2));

// Phase A: matches_baseline must be TRUE before Phase D edits begin.
// Phase D: this script is updated atomically with the baseline snapshot;
//          the assertion becomes "matches_baseline === true AFTER Phase D
//          rewrites baseline to include the new _verifierContracts slot".
if (!sameLayout) {
  console.error("STORAGE_LAYOUT_DIVERGENCE: baseline + current differ. If this is intentional (Phase D), update the baseline snapshot in the same commit.");
  process.exit(1);
}
process.exit(0);
