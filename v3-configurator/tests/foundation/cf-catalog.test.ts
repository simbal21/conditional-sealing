// Foundation: CF catalog (Stage 4, CF-01..CF-07) sanity.

import { describe, expect, it } from "vitest";
import { CF_BY_ID, CF_CATALOG, CF_CATALOG_COUNT } from "../../src/types/cf-codes.js";

describe("@cealis/v3-configurator — CF catalog (§4.5)", () => {
  it("CF_CATALOG_COUNT is 7", () => {
    expect(CF_CATALOG_COUNT).toBe(7);
  });

  it("CF_CATALOG length is 7", () => {
    expect(CF_CATALOG.length).toBe(7);
  });

  it("CF codes are CF-01 through CF-07 contiguously in order", () => {
    for (let i = 0; i < 7; i++) {
      const expected = `CF-${String(i + 1).padStart(2, "0")}`;
      const entry = CF_CATALOG[i];
      expect(entry).toBeDefined();
      if (entry === undefined) continue;
      expect(entry.id).toBe(expected);
    }
  });

  it("every CF descriptor has non-empty label + specification prose", () => {
    for (const desc of CF_CATALOG) {
      expect(desc.label.length).toBeGreaterThan(0);
      expect(desc.specification.length).toBeGreaterThan(0);
    }
  });

  it("CF-01 enforces Art. 22 legal-effect safeguard with five conjuncts", () => {
    const cf01 = CF_BY_ID.get("CF-01");
    expect(cf01).toBeDefined();
    if (cf01 === undefined) return;
    expect(cf01.label).toBe("Art. 22 legal-effect safeguard");
    expect(cf01.specification).toContain("all five conjuncts must hold");
    // Check each of the five conjuncts is referenced by its keyword.
    expect(cf01.specification).toContain("reveal_challenge_window");
    expect(cf01.specification).toContain("ceremony_resolver");
    expect(cf01.specification).toContain("eligible_challengers_reveal");
    expect(cf01.specification).toContain("minimum_shred_latency");
    expect(cf01.specification).toContain("cealis_class_wide_halt_opt_out");
  });

  it("CF-07 has primary failure code CF-07_MULTIPARTY_SIGNAL_DEFAULT", () => {
    const cf07 = CF_BY_ID.get("CF-07");
    expect(cf07).toBeDefined();
    if (cf07 === undefined) return;
    expect(cf07.primary_failure_code).toBe("CF-07_MULTIPARTY_SIGNAL_DEFAULT");
  });

  it("CF-07 has per-PDA opt-out branch + sub-class 3 class-wide opt-out", () => {
    const cf07 = CF_BY_ID.get("CF-07");
    expect(cf07).toBeDefined();
    if (cf07 === undefined) return;
    expect(cf07.has_opt_out_branch).toBe(true);
    expect(cf07.class_wide_opt_out_requires_sub_class_3).toBe(true);
    expect(cf07.specification).toContain("k >= 2");
    expect(cf07.specification).toContain("independent oracle operators");
    expect(cf07.specification).toContain("Class-wide opt-out requires sub-class 3 governance");
  });

  it("CF-02 forbids halt opt-out when legal_effect_expected", () => {
    const cf02 = CF_BY_ID.get("CF-02");
    expect(cf02).toBeDefined();
    if (cf02 === undefined) return;
    expect(cf02.specification).toContain("legal_effect_expected = true");
    expect(cf02.specification).toContain("cealis_class_wide_halt_opt_out");
    expect(cf02.specification).toContain("must be false");
  });

  it("CF-03 enforces long-TTL conditional-recipient redundancy", () => {
    const cf03 = CF_BY_ID.get("CF-03");
    expect(cf03).toBeDefined();
    if (cf03 === undefined) return;
    expect(cf03.specification).toContain("fire_time_ttl_estimate > 5 years");
    expect(cf03.specification).toContain("n >= 2k");
    expect(cf03.specification).toContain("emergency_response_bricking_acknowledgment");
  });

  it("CF-05 requires Phase 2 for legal-effect or partner-ready PDAs", () => {
    const cf05 = CF_BY_ID.get("CF-05");
    expect(cf05).toBeDefined();
    if (cf05 === undefined) return;
    expect(cf05.specification).toContain("g4_phase");
    expect(cf05.specification).toContain("Phase 2");
  });
});
