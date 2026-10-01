// Foundation: CI catalog (Stage 2, CI-01..CI-20) sanity.

import { describe, expect, it } from "vitest";
import { CI_BY_ID, CI_CATALOG, CI_CATALOG_COUNT } from "../../src/types/ci-codes.js";

describe("@cealis/v3-configurator — CI catalog (§4.3)", () => {
  it("CI_CATALOG_COUNT is 20 (per spec §4.3 closed catalog)", () => {
    expect(CI_CATALOG_COUNT).toBe(20);
  });

  it("CI_CATALOG length is 20", () => {
    expect(CI_CATALOG.length).toBe(20);
  });

  it("CI codes are CI-01 through CI-20 contiguously in order", () => {
    for (let i = 0; i < 20; i++) {
      const expected = `CI-${String(i + 1).padStart(2, "0")}`;
      const entry = CI_CATALOG[i];
      expect(entry).toBeDefined();
      if (entry === undefined) continue;
      expect(entry.id).toBe(expected);
    }
  });

  it("every CI descriptor has non-empty invariant and configurator_check prose", () => {
    for (const desc of CI_CATALOG) {
      expect(desc.invariant.length).toBeGreaterThan(0);
      expect(desc.configurator_check.length).toBeGreaterThan(0);
    }
  });

  it("CI_BY_ID resolves each catalog code to its descriptor", () => {
    for (const desc of CI_CATALOG) {
      expect(CI_BY_ID.get(desc.id)).toBe(desc);
    }
  });

  it("CI-07 invariant is 'Mode 3 RESERVED' (highest-leakage paraphrase risk)", () => {
    const ci07 = CI_BY_ID.get("CI-07");
    expect(ci07).toBeDefined();
    if (ci07 === undefined) return;
    expect(ci07.invariant).toBe("Mode 3 RESERVED");
    expect(ci07.configurator_check).toContain("WALLET_EIP1271");
  });

  it("CI-12 enforces mandatory NOT post_challenge_reveal_in_progress shred guardrail", () => {
    const ci12 = CI_BY_ID.get("CI-12");
    expect(ci12).toBeDefined();
    if (ci12 === undefined) return;
    expect(ci12.configurator_check).toContain("NOT post_challenge_reveal_in_progress");
  });

  it("CI-13 binds pda_root to S2-1 §3.3 29-field order", () => {
    const ci13 = CI_BY_ID.get("CI-13");
    expect(ci13).toBeDefined();
    if (ci13 === undefined) return;
    expect(ci13.invariant).toContain("S2-1 §3.3 29-field order");
  });

  it("CI-20 forbids DisclosureRegistry authorizing escrow reveal", () => {
    const ci20 = CI_BY_ID.get("CI-20");
    expect(ci20).toBeDefined();
    if (ci20 === undefined) return;
    expect(ci20.invariant).toBe("DisclosureRegistry cannot authorize escrow reveal");
  });
});
