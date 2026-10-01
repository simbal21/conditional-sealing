import { describe, expect, it } from "vitest";
import { validateCf07 } from "../../src/validate/cross-field/index.js";

describe("CF-07 per-PDA opt-out branch", () => {
  it("passes when the archetype permits opt-out and the partner acknowledgment is inspection-bound", () => {
    const failures = validateCf07({
      archetype_template: { permits_per_pda_mps_opt_out: true },
      pda: {
        use_case: "testament",
        archetype: "irreversible_personal_reveal",
        trust_tier: "B",
        firing_condition_depends_on_external_event_source: true,
        per_pda_mps_opt_out: true,
        inspection_surface: {
          partner_acknowledgments: ["multi_oracle_opt_out"],
        },
      },
    });
    expect(failures).toHaveLength(0);
  });
});
