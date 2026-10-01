// Foundation: class-table load-bearing constants (§5.4 consistency check inputs).

import { describe, expect, it } from "vitest";
import {
  CHILD_ROW_COUNT,
  CHILD_ROW_IDS,
  EXECUTABLE_INTEGER_ROOT_COUNT,
  EXECUTABLE_ROW_COUNT,
  FULLY_DECOMPOSED_ROOT_IDS,
  parseRowId,
  ROOT_FAMILY_ID_MAX,
} from "../../src/types/class-table.js";

describe("@cealis/v3-configurator — class-table constants (§5.4)", () => {
  it("EXECUTABLE_ROW_COUNT is 103", () => {
    expect(EXECUTABLE_ROW_COUNT).toBe(103);
  });

  it("ROOT_FAMILY_ID_MAX is 91 (contiguous 1..91 family namespace)", () => {
    expect(ROOT_FAMILY_ID_MAX).toBe(91);
  });

  it("EXECUTABLE_INTEGER_ROOT_COUNT is 81 (91 - 10 fully decomposed)", () => {
    expect(EXECUTABLE_INTEGER_ROOT_COUNT).toBe(81);
  });

  it("CHILD_ROW_COUNT is 22", () => {
    expect(CHILD_ROW_COUNT).toBe(22);
  });

  it("CHILD_ROW_IDS has 22 entries", () => {
    expect(CHILD_ROW_IDS.length).toBe(22);
  });

  it("81 + 22 === 103 (executable integer roots + child rows = total)", () => {
    expect(EXECUTABLE_INTEGER_ROOT_COUNT + CHILD_ROW_COUNT).toBe(EXECUTABLE_ROW_COUNT);
  });

  it("FULLY_DECOMPOSED_ROOT_IDS has exactly 10 entries", () => {
    expect(FULLY_DECOMPOSED_ROOT_IDS.length).toBe(10);
  });

  it("FULLY_DECOMPOSED_ROOT_IDS contains the verbatim 10 IDs from §5.2", () => {
    // Verified by grep against docs/specs/configurator-pda-spec.md §5.2 —
    // integer roots that are ABSENT from the table but whose children
    // ARE present.
    expect(FULLY_DECOMPOSED_ROOT_IDS).toEqual([
      "56",
      "60",
      "62",
      "63",
      "64",
      "69",
      "77",
      "79",
      "87",
      "90",
    ]);
  });

  it("CHILD_ROW_IDS contains the verbatim 22 IDs from §5.2", () => {
    expect(CHILD_ROW_IDS).toEqual([
      "14.1",
      "15.1",
      "56.1",
      "56.2",
      "60.1",
      "60.2",
      "62.1",
      "62.2",
      "63.1",
      "63.2",
      "64.1",
      "64.2",
      "69.1",
      "69.2",
      "77.1",
      "77.2",
      "79.1",
      "79.2",
      "87.1",
      "87.2",
      "90.1",
      "90.2",
    ]);
  });

  it("every CHILD_ROW_ID parses to a valid root+child shape", () => {
    for (const id of CHILD_ROW_IDS) {
      const parsed = parseRowId(id);
      expect(parsed).not.toBeNull();
      if (parsed === null) continue;
      expect(parsed.child).not.toBeNull();
    }
  });

  it("every FULLY_DECOMPOSED_ROOT_ID has at least one child in CHILD_ROW_IDS", () => {
    for (const root of FULLY_DECOMPOSED_ROOT_IDS) {
      const hasChild = CHILD_ROW_IDS.some((c) => c.startsWith(`${root}.`));
      expect(hasChild, `root ${root} must have a child in CHILD_ROW_IDS`).toBe(true);
    }
  });

  it("parseRowId returns null for non-canonical strings", () => {
    expect(parseRowId("")).toBeNull();
    expect(parseRowId("abc")).toBeNull();
    expect(parseRowId("1.")).toBeNull();
    expect(parseRowId(".1")).toBeNull();
    expect(parseRowId("1.2.3")).toBeNull();
  });

  it("parseRowId correctly parses integer roots and decomposed children", () => {
    expect(parseRowId("1")).toEqual({ root: "1", child: null });
    expect(parseRowId("91")).toEqual({ root: "91", child: null });
    expect(parseRowId("14.1")).toEqual({ root: "14", child: "1" });
    expect(parseRowId("56.2")).toEqual({ root: "56", child: "2" });
  });
});
