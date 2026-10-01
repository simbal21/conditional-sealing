import { describe, expect, it } from "vitest";
import { validateCf07 } from "../../src/validate/cross-field/index.js";

describe("CF-07 irreversible-archetype MultiPartySignal default", () => {
  it("fails when an irreversible external-trigger archetype has no MultiPartySignal", () => {
    const failures = validateCf07({
      pda: {
        use_case: "testament",
        archetype: "irreversible_personal_reveal",
        trust_tier: "B",
        firing_condition_depends_on_external_event_source: true,
      },
    });
    expect(failures).toHaveLength(1);
    expect(failures[0]?.stage_code).toContain(
      "CF-07_MULTIPARTY_SIGNAL_DEFAULT",
    );
    expect(failures[0]?.internal.failed_predicate).toBe(
      "missing MultiPartySignal default",
    );
  });

  it("fails when k is below the k >= 2 default", () => {
    const failures = validateCf07({
      pda: {
        use_case: "m_and_a",
        archetype: "multi_party_commercial_escrow",
        trust_tier: "B",
        firing_condition_depends_on_external_event_source: true,
        multi_party_signal: {
          k: 1,
          n: 3,
          independent_operators: true,
          signal_digest_bound: true,
          oracle_refs: [
            {
              id: "counsel-a",
              tier: "B",
              operator_id: "op-a",
              signer_identity: "sig-a",
            },
            {
              id: "counsel-b",
              tier: "B",
              operator_id: "op-b",
              signer_identity: "sig-b",
            },
          ],
        },
      },
    });
    expect(
      failures.map((failure) => failure.internal.failed_predicate),
    ).toContain(
      "MultiPartySignal k is below irreversible-archetype default k >= 2",
    );
  });
});
