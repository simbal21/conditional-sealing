import { describe, expect, it } from "vitest";
import { validateCrossFieldRules } from "../../src/validate/cross-field/index.js";

describe("Stage 4 cross-field dispatcher emits all failures", () => {
  it("does not short-circuit a legal-effect Tier B PDA with multiple relational failures", () => {
    const failures = validateCrossFieldRules({
      pda: {
        legal_effect_expected: true,
        trust_tier: "B",
        relevant_reveal_condition_tiers: ["B"],
        reveal_challenge_window_seconds: 0n,
        archetype_floor_seconds: 14n * 24n * 60n * 60n,
        ceremony_resolver: { type: "bot_endpoint" },
        eligible_challengers_reveal: ["operator"],
        subject_id: "subject",
        minimum_shred_latency_seconds: 0n,
        cealis_class_wide_halt_opt_out: true,
        g4_phase: 1,
      },
    });

    const codes = failures.map((failure) => failure.stage_code);
    expect(failures.length).toBeGreaterThanOrEqual(6);
    expect(
      codes.some((code) => code.includes("ART22_CHALLENGE_WINDOW_BELOW_FLOOR")),
    ).toBe(true);
    expect(
      codes.some((code) =>
        code.includes("ART22_RESOLVER_NOT_HUMAN_OR_JUDICIAL"),
      ),
    ).toBe(true);
    expect(
      codes.some((code) =>
        code.includes("ART22_SUBJECT_NOT_ELIGIBLE_CHALLENGER"),
      ),
    ).toBe(true);
    expect(
      codes.some((code) =>
        code.includes("LEGAL_EFFECT_HALT_OPT_OUT_FORBIDDEN"),
      ),
    ).toBe(true);
    expect(
      codes.some((code) =>
        code.includes("LEGAL_EFFECT_OR_PARTNER_READY_REQUIRES_PHASE_2"),
      ),
    ).toBe(true);
  });
});
