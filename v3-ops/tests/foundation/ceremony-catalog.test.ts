import { describe, it, expect } from "vitest";
import { CEREMONY_CATALOG, findCeremony, ceremonyAtNumber } from "../../src/catalog/index.js";

/**
 * Drift catch #1: 17 catalog rows matching S2-6 §2 (16) + §16.5 (1) =
 * App. A 17 timeline diagrams + App. B 17×8 invariant matrix.
 */
describe("CEREMONY_CATALOG (S2-6 §2 + §16.5)", () => {
  it("has exactly 17 rows", () => {
    expect(CEREMONY_CATALOG).toHaveLength(17);
  });

  it("row numbers are 1..17 consecutive", () => {
    const numbers = CEREMONY_CATALOG.map((c) => c.number);
    expect(numbers).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]);
  });

  it("slugs are unique", () => {
    const slugs = CEREMONY_CATALOG.map((c) => c.slug);
    const unique = new Set(slugs);
    expect(unique.size).toBe(slugs.length);
  });

  it("each row has a non-empty name + specSection", () => {
    for (const c of CEREMONY_CATALOG) {
      expect(c.name.length).toBeGreaterThan(0);
      expect(c.specSection.length).toBeGreaterThan(0);
    }
  });

  it("findCeremony returns the right row by slug", () => {
    expect(findCeremony("g4-binary-hash-update")?.number).toBe(1);
    expect(findCeremony("governance-phase2-transition")?.number).toBe(17);
    expect(findCeremony("nonsense")).toBeUndefined();
  });

  it("ceremonyAtNumber returns the right row", () => {
    expect(ceremonyAtNumber(11)?.slug).toBe("shred-trigger");
    expect(ceremonyAtNumber(17)?.slug).toBe("governance-phase2-transition");
    expect(ceremonyAtNumber(99)).toBeUndefined();
  });

  it("rows 1, 2, 4, 6, 11, 13, 16, 17 cover the spec sections of priority ceremonies", () => {
    expect(ceremonyAtNumber(1)?.specSection).toBe("§3");
    expect(ceremonyAtNumber(2)?.specSection).toBe("§4");
    expect(ceremonyAtNumber(4)?.specSection).toBe("§6");
    expect(ceremonyAtNumber(6)?.specSection).toBe("§7A");
    expect(ceremonyAtNumber(11)?.specSection).toBe("§11");
    expect(ceremonyAtNumber(13)?.specSection).toBe("§12.7");
    expect(ceremonyAtNumber(16)?.specSection).toBe("§14.3");
    expect(ceremonyAtNumber(17)?.specSection).toBe("§16.5");
  });
});
