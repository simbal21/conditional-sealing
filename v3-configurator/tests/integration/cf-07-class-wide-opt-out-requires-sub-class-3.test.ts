import { describe, expect, it } from "vitest";
import { routeClassWideOptOut } from "../../src/multi-oracle/index.js";
import { validateCf07 } from "../../src/validate/cross-field/index.js";

describe("CF-07 class-wide opt-out governance", () => {
  it("fails without sub-class 3 governance and routes to the sub-class 3 authority", () => {
    const route = routeClassWideOptOut();
    const failures = validateCf07({
      pda: {
        use_case: "dead_man_switch",
        archetype: "conditional_reveal_liveness",
        trust_tier: "B",
        firing_condition_depends_on_external_event_source: true,
        class_wide_mps_opt_out: true,
      },
    });

    expect(route.sub_class).toBe(3);
    expect(route.authority).toBe(
      "CealisSecurityMultisig plus EmergencyGovernance",
    );
    expect(failures).toHaveLength(1);
    expect(failures[0]?.internal.governance_sub_class).toBe(3);
    expect(failures[0]?.stage_code).toContain(
      "CF-07_MULTIPARTY_SIGNAL_DEFAULT",
    );
  });
});
