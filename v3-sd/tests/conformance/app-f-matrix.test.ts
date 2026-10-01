// App. F conformance matrix — DEFERRED to M7/M8.
//
// dw-quality REJECTED the earlier M6 Phase E shipment of this test because
// the original implementation synthesized FIXTURE_BY_ROW in-test and asserted
// on its own synthesis (a tautology, not a conformance assertion). The 54
// App. F rows (SD-CFG-001…SD-TEST-004) were NEVER actually verified against
// real fixtures. Marking PRO-490 Done on that surface would have been a
// false claim of S2-7 conformance per §0.5 line 49.
//
// Resolution at M6 Phase F closeout: explicit deferral, NOT smoke-test passes.
//
// What lands at M6 (HONEST):
//   - 28 App. B vector files exist at v3-sd/test-vectors/
//   - Every vector file carries `"status": "PLACEHOLDER_M6_AWAITING_PRODUCTION_REGEN"`
//   - The vectors are structurally-correct JSON shape but cryptographically-meaningless
//     (digests/salts/commitments/proofs are placeholders, NOT live-code-path outputs)
//
// What is DEFERRED to M7/M8:
//   1. Regenerating every vector from the live @cealis/v3-sd code paths
//      (drop the PLACEHOLDER marker)
//   2. Building a row-by-row App. F conformance test that loads each
//      real fixture and asserts the §App.F normative criterion per row
//   3. The "100% row × fixture coverage" GUARD §21 claim (text patched to
//      reflect the deferral)
//
// This file asserts the deferral state is honest:
//   (a) The PLACEHOLDER marker is present on every vector file
//   (b) The deferral is documented in SPEC-COMPLIANCE-GUARD-M6 §21
//   (c) PRO-490 closeout must NOT claim S2-7 conformance at M6
//
// When a future M7/M8 mission ships real vectors + real conformance:
//   - Remove the PLACEHOLDER marker from every vector file
//   - Replace this file with a real row-by-row App. F conformance test
//   - Patch SPEC-COMPLIANCE-GUARD-M6 §21 to remove the deferral language

import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const VECTOR_DIR = resolve(__dirname, "..", "..", "test-vectors");
const GUARD_PATH = resolve(__dirname, "..", "..", "SPEC-COMPLIANCE-GUARD-M6.md");
const PLACEHOLDER_STATUS = "PLACEHOLDER_M6_AWAITING_PRODUCTION_REGEN";

const APP_F_ROWS = [
  "SD-CFG-001", "SD-CFG-002", "SD-CFG-003", "SD-CFG-004", "SD-CFG-005",
  "SD-TEE-001", "SD-TEE-002", "SD-TEE-003", "SD-TEE-004", "SD-TEE-005", "SD-TEE-006",
  "SD-TAG-001", "SD-TAG-002",
  "SD-FIELD-001", "SD-FIELD-002", "SD-FIELD-003", "SD-FIELD-004",
  "SD-COM-001", "SD-COM-002",
  "SD-MERKLE-001", "SD-MERKLE-002", "SD-MERKLE-003", "SD-MERKLE-004",
  "SD-BIND-001", "SD-BIND-002",
  "SD-PRED-001", "SD-PRED-002", "SD-PRED-003", "SD-PRED-004", "SD-PRED-005",
  "SD-PLONK-001", "SD-PLONK-002", "SD-PLONK-003", "SD-PLONK-004", "SD-PLONK-005",
  "SD-API-001", "SD-API-002", "SD-API-003",
  "SD-SDK-001", "SD-SDK-002", "SD-SDK-003", "SD-SDK-004", "SD-SDK-005",
  "SD-CHAIN-001", "SD-CHAIN-002", "SD-CHAIN-003", "SD-CHAIN-004",
  "SD-SHRED-001", "SD-SHRED-002", "SD-SHRED-003",
  "SD-TEST-001", "SD-TEST-002", "SD-TEST-003", "SD-TEST-004",
] as const;

describe("App. F conformance — DEFERRED to M7/M8 (HARD-3 + HARD-4 resolution)", () => {
  it("App. F row catalog is enumerated for M7/M8 reference (54 rows)", () => {
    expect(APP_F_ROWS.length).toBe(54);
    expect(new Set(APP_F_ROWS).size).toBe(APP_F_ROWS.length);
  });

  it("Every test-vector file carries the PLACEHOLDER_M6_AWAITING_PRODUCTION_REGEN marker", () => {
    const files = readdirSync(VECTOR_DIR).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThan(0);

    const missingMarker: string[] = [];
    for (const file of files) {
      const parsed = JSON.parse(readFileSync(resolve(VECTOR_DIR, file), "utf-8"));
      if (parsed.status !== PLACEHOLDER_STATUS) {
        missingMarker.push(file);
      }
    }

    expect(
      missingMarker,
      `Vector files missing PLACEHOLDER status — either they are real M7/M8 production vectors ` +
        `(in which case this conformance test must be replaced with a real row-by-row App. F test ` +
        `AND GUARD §21 deferral language removed) OR they are bogus and must regain the marker: ` +
        `${missingMarker.join(", ")}`,
    ).toEqual([]);
  });

  it("SPEC-COMPLIANCE-GUARD-M6 §21 explicitly defers App. F conformance to M7/M8", () => {
    const guard = readFileSync(GUARD_PATH, "utf-8");
    expect(
      guard,
      "GUARD §21 must explicitly mark App. F conformance as DEFERRED to M7/M8 (HARD-3 resolution)",
    ).toMatch(/App\.\s*F\s+conformance.*DEFERRED\s+to\s+M7\/M8/i);
  });

  it("M6 closeout must NOT claim S2-7 conformance — fail explicit if any vector lacks the marker", () => {
    // Phase F closeout tripwire: this test fails if anyone marks PRO-490 Done while vectors are still placeholders.
    // When real vectors land at M7/M8, this test gets replaced with row-by-row conformance.
    const files = readdirSync(VECTOR_DIR).filter((f) => f.endsWith(".json"));
    const placeholderCount = files.filter((f) => {
      const parsed = JSON.parse(readFileSync(resolve(VECTOR_DIR, f), "utf-8"));
      return parsed.status === PLACEHOLDER_STATUS;
    }).length;

    // INVARIANT (M6 honest state): all vectors are placeholders.
    // At M7/M8 real vectors land and this test gets replaced by a real conformance test.
    expect(placeholderCount).toBe(files.length);
  });
});
