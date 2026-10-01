// Foundation: governance metadata interface (§6.8).

import { describe, expect, it } from "vitest";
import {
  SUB_CLASS_METADATA,
  SUB_CLASS_METADATA_COUNT,
} from "../../src/types/governance-metadata.js";

describe("@cealis/v3-configurator — governance metadata (§6.8)", () => {
  it("SUB_CLASS_METADATA_COUNT is 5", () => {
    expect(SUB_CLASS_METADATA_COUNT).toBe(5);
  });

  it("SUB_CLASS_METADATA has entries for sub-classes 1..5", () => {
    for (const sc of [1, 2, 3, 4, 5] as const) {
      expect(SUB_CLASS_METADATA.has(sc), `sub-class ${sc} must be present`).toBe(true);
    }
  });

  it("sub-class 1 = TimelockController-7d, 604800 delay, S2-6-CER-01", () => {
    const sc1 = SUB_CLASS_METADATA.get(1);
    expect(sc1).toBeDefined();
    if (sc1 === undefined) return;
    expect(sc1.authority_ref).toBe("TimelockController-7d");
    expect(sc1.delay_seconds).toBe(604800);
    expect(sc1.s2_6_ceremony_ref).toBe("S2-6-CER-01");
    expect(sc1.on_chain_event).toBe("PDAPlusAdditionQueued / PDAPlusAdditionExecuted");
    expect(sc1.inspection_visibility).toBe(
      "Public queued diff before activation; partner inspection after activation.",
    );
  });

  it("sub-class 2 = CealisSecurityMultisig, S2-6-CER-02 (PDAPlusEntryDeprecated)", () => {
    const sc2 = SUB_CLASS_METADATA.get(2);
    expect(sc2).toBeDefined();
    if (sc2 === undefined) return;
    expect(sc2.authority_ref).toBe("CealisSecurityMultisig");
    expect(sc2.s2_6_ceremony_ref).toBe("S2-6-CER-02");
    expect(sc2.on_chain_event).toBe("PDAPlusEntryDeprecated / PDAPlusDeprecationCleared");
  });

  it("sub-class 3 = CealisSecurityMultisig + EmergencyGovernance circuit breaker", () => {
    const sc3 = SUB_CLASS_METADATA.get(3);
    expect(sc3).toBeDefined();
    if (sc3 === undefined) return;
    expect(sc3.authority_ref).toBe("CealisSecurityMultisig plus EmergencyGovernance");
    expect(sc3.s2_6_ceremony_ref).toBe("S2-6-CER-03");
    expect(sc3.on_chain_event).toBe("PDAPlusEmergencyTriggered / PDAPlusEmergencyRestored");
  });

  it("sub-class 4 = TimelockController-7d constraint adjustment, S2-6-CER-04", () => {
    const sc4 = SUB_CLASS_METADATA.get(4);
    expect(sc4).toBeDefined();
    if (sc4 === undefined) return;
    expect(sc4.authority_ref).toBe("TimelockController-7d");
    expect(sc4.delay_seconds).toBe(604800);
    expect(sc4.s2_6_ceremony_ref).toBe("S2-6-CER-04");
    expect(sc4.on_chain_event).toBe(
      "PDAPlusConstraintAdjustmentQueued / PDAPlusConstraintAdjustmentExecuted",
    );
  });

  it("sub-class 5 = RuleAdditionTimelockController + code-release author-lock", () => {
    const sc5 = SUB_CLASS_METADATA.get(5);
    expect(sc5).toBeDefined();
    if (sc5 === undefined) return;
    expect(sc5.authority_ref).toBe(
      "RuleAdditionTimelockController plus code-release author-lock",
    );
    expect(sc5.delay_seconds).toBe(604800);
    expect(sc5.s2_6_ceremony_ref).toBe("S2-6-CER-05");
    expect(sc5.on_chain_event).toBe("PDAPlusRuleAdditionQueued / PDAPlusRuleActivated");
  });

  it("every entry has all 7 GovernanceMetadata fields populated", () => {
    for (const [_sc, meta] of SUB_CLASS_METADATA) {
      expect(meta.authority_ref.length).toBeGreaterThan(0);
      expect(meta.threshold_ref.length).toBeGreaterThan(0);
      // delay_seconds + max_duration_seconds can be 0 (sub-class 3) or
      // compound strings — both forms accepted by spec.
      expect(meta.delay_seconds !== undefined).toBe(true);
      expect(meta.max_duration_seconds !== undefined).toBe(true);
      expect(meta.on_chain_event.length).toBeGreaterThan(0);
      expect(meta.inspection_visibility.length).toBeGreaterThan(0);
      expect(meta.s2_6_ceremony_ref.length).toBeGreaterThan(0);
    }
  });
});
