// Foundation: coverage sidecar (§5.4A) shape sanity.

import { describe, expect, it } from "vitest";
import {
  CONDITION_MODULE_COUNT,
  CONDITION_MODULE_NAMES,
  REQUIRED_CONDITION_MODULE_ROW_IDS,
  REQUIRED_VIEW_ROW_IDS,
  VIEW_COUNT,
  VIEW_NAMES,
} from "../../src/types/coverage-sidecar.js";
import { parseRowId } from "../../src/types/class-table.js";

describe("@cealis/v3-configurator — coverage sidecar shape (§5.4A)", () => {
  it("VIEW_COUNT is 7", () => {
    expect(VIEW_COUNT).toBe(7);
  });

  it("CONDITION_MODULE_COUNT is 9", () => {
    expect(CONDITION_MODULE_COUNT).toBe(9);
  });

  it("VIEW_NAMES has exactly 7 entries (Enforcement / TamperProof / SelectiveDisclosure / Commercial / Legal / UseCaseFlex / PartnerFit)", () => {
    expect(VIEW_NAMES).toEqual([
      "Enforcement",
      "TamperProof",
      "SelectiveDisclosure",
      "Commercial",
      "Legal",
      "UseCaseFlex",
      "PartnerFit",
    ]);
  });

  it("CONDITION_MODULE_NAMES has exactly 9 entries (PaymentObligation..Composed)", () => {
    expect(CONDITION_MODULE_NAMES).toEqual([
      "PaymentObligation",
      "TimeLock",
      "SubjectInitiated",
      "HeartbeatMissed",
      "OracleAttestation",
      "MultiPartySignal",
      "DeadManSwitch",
      "ConsentGate",
      "Composed",
    ]);
  });

  it("every VIEW_NAMES key has a row-id list in REQUIRED_VIEW_ROW_IDS", () => {
    for (const view of VIEW_NAMES) {
      const ids = REQUIRED_VIEW_ROW_IDS[view];
      expect(ids).toBeDefined();
      expect(Array.isArray(ids)).toBe(true);
      expect(ids.length).toBeGreaterThan(0);
    }
  });

  it("every CONDITION_MODULE_NAMES key has a row-id list in REQUIRED_CONDITION_MODULE_ROW_IDS", () => {
    for (const moduleName of CONDITION_MODULE_NAMES) {
      const ids = REQUIRED_CONDITION_MODULE_ROW_IDS[moduleName];
      expect(ids).toBeDefined();
      expect(Array.isArray(ids)).toBe(true);
      expect(ids.length).toBeGreaterThan(0);
    }
  });

  it("every required row id (views + modules) parses to a valid RowId", () => {
    for (const view of VIEW_NAMES) {
      for (const id of REQUIRED_VIEW_ROW_IDS[view]) {
        const parsed = parseRowId(id);
        expect(parsed, `view ${view} row id ${id} must parse`).not.toBeNull();
      }
    }
    for (const moduleName of CONDITION_MODULE_NAMES) {
      for (const id of REQUIRED_CONDITION_MODULE_ROW_IDS[moduleName]) {
        const parsed = parseRowId(id);
        expect(
          parsed,
          `condition-module ${moduleName} row id ${id} must parse`,
        ).not.toBeNull();
      }
    }
  });

  it("verbatim spot-checks from §5.4A", () => {
    // Enforcement → `3`, `22`, `56.1`, `56.2`, `61`, `70`
    expect(REQUIRED_VIEW_ROW_IDS.Enforcement).toEqual(["3", "22", "56.1", "56.2", "61", "70"]);
    // MultiPartySignal → `61`, `70`, `69.2`
    expect(REQUIRED_CONDITION_MODULE_ROW_IDS.MultiPartySignal).toEqual(["61", "70", "69.2"]);
    // Selective Disclosure → `8`, `9`, `10`, `76`
    expect(REQUIRED_VIEW_ROW_IDS.SelectiveDisclosure).toEqual(["8", "9", "10", "76"]);
  });
});
