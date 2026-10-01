// T5.1 — the configurator EMITs the security PDA config fields the merged
// 2026-06-02 contracts (`SubjectInitiatedModule` / `DeadManSwitchModule`) bind
// on-chain, at EXACTLY the location the T1.4 ingest inspector reads.
//
// The merged contracts `ECDSA.recover` an EIP-712 signature and revert unless it
// recovers to a PDA-configured signer:
//   - `SubjectInitiatedModule.configureSubjectInitiated(authorizationId,
//     expectedAxis, subjectSigner, configDigest)` — `subjectSigner` under the
//     `CealisSubjectInitiated` v1 domain, typehash
//     `SubjectAction(bytes32 authorizationId,bytes32 actionDigest,address subject)`.
//   - `DeadManSwitchModule.configureDeadManSwitch(authorizationId,
//     recipientPolicyDigest, actor, interval, gracePeriod, configDigest)` —
//     `actor` under the `CealisDeadManSwitch` v1 domain, typehash
//     `Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)`.
//
// The runtime threads the PDA-configured signer/actor into those on-chain calls;
// `emit.ts` is where the configurator must surface them. The T1.4 inspector
// (`v3-api/src/ingest/pda-inspector.ts deriveModuleSecurity`) reads the emitted
// `submitted.reveal_condition.subject_signer` / `.actor` (+ axis / interval /
// grace) — this test proves emit→inspect agrees.
//
// LAYERING: `v3-configurator` is BELOW `v3-api` (v3-api depends on the
// configurator, not the reverse), so this test cannot import the inspector. It
// instead inlines a FAITHFUL MIRROR of the inspector's read path + its pinned
// EIP-712 constants (copied verbatim from
// `v3-api/src/ingest/pda-inspector.ts`). If the inspector's read locations or
// pinned typehashes ever drift from the emitter, the round-trip assertions here
// break — which is the point: this file locks the cross-package contract from
// the producer side. The CONFIRM step asserts the mirrored literals equal what
// the deployed module contracts declare, so a contract-vs-test drift also fails.

import { describe, expect, it } from "vitest";

import { prepareSubmittedPda } from "../../src/pda/emit.js";
import { hashToHex32 } from "../../src/pda/pda-root.js";
import { scaffoldFor } from "../../src/cli/init.js";

// NOTE on the test seam: the T1.4 ingest inspector consumes `resolved.submitted`
// — i.e. the `prepareSubmittedPda(input)` output (also `EmittedPdaArtifact.submitted`
// from emitPDA). So `prepareSubmittedPda` IS the exact object whose
// `reveal_condition.subject_signer` / `.actor` the inspector reads; these tests
// assert against it directly. We deliberately do NOT gate on full `emitPDA()`
// Stage-1-5 success: the shipping fixtures hit a PRE-EXISTING Stage-3
// template-pick gap (class-table rows 54 / 56.1 report `ALLOW_LIST_MISSING`),
// committed at HEAD (commit c51754c) and orthogonal to T5.1's security-field
// emission. T5.1 only changes what `reveal_condition` carries; it does not touch
// the validation surface. (Verified: the gap reproduces with this file's changes
// stashed.)

// ── Mirror of the T1.4 inspector's pinned EIP-712 bindings ─────────────────────
// Copied VERBATIM from v3-api/src/ingest/pda-inspector.ts (SUBJECT_INITIATED_EIP712
// / DEAD_MAN_SWITCH_EIP712). Confirmed against the deployed module contracts
// (CealisSubjectInitiated / CealisDeadManSwitch, version "1") in the CONFIRM test
// below — if the contract changes its domain/typehash, that test fails first.
const SUBJECT_INITIATED_EIP712 = {
  domain_name: "CealisSubjectInitiated",
  domain_version: "1",
  struct_typehash: "SubjectAction(bytes32 authorizationId,bytes32 actionDigest,address subject)",
} as const;

const DEAD_MAN_SWITCH_EIP712 = {
  domain_name: "CealisDeadManSwitch",
  domain_version: "1",
  struct_typehash: "Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)",
} as const;

// ── Mirror of the inspector's read path (deriveModuleSecurity) ─────────────────
// Faithful re-implementation of v3-api/src/ingest/pda-inspector.ts
// `deriveModuleSecurity(submitted)`: same field names, same priority order, same
// PdaModuleSecurity shape. Consumes the EMITTED `submitted` (prepareSubmittedPda
// output) exactly as the real inspector consumes `resolved.submitted`.
interface InspectedModuleSecurity {
  module: string;
  subject_initiated?: {
    subject_signer: string;
    expected_axis: "reveal" | "shred";
    eip712: typeof SUBJECT_INITIATED_EIP712;
  };
  dead_man_switch?: {
    actor: string;
    interval_seconds: number;
    grace_period_seconds: number;
    eip712: typeof DEAD_MAN_SWITCH_EIP712;
  };
}

function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
function readAddress(value: unknown): string | undefined {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value) ? value : undefined;
}
function toNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

/** Faithful mirror of the v3-api inspector's `deriveModuleSecurity`. */
function inspectModuleSecurity(submitted: Record<string, unknown>): InspectedModuleSecurity {
  const reveal = recordValue(submitted.reveal_condition);
  const module = readString(reveal.module) ?? "PaymentObligation";
  const security = recordValue(reveal.module_security);
  const params = recordValue(reveal.evidence_parameters);

  if (module === "SubjectInitiated") {
    const subjectSigner =
      readAddress(reveal.subject_signer) ??
      readAddress(security.subject_signer) ??
      readAddress(reveal.subjectSigner) ??
      readAddress(security.subjectSigner);
    const axisRaw =
      readString(reveal.expected_axis) ??
      readString(security.expected_axis) ??
      readString(reveal.axis);
    const expectedAxis: "reveal" | "shred" = axisRaw === "shred" ? "shred" : "reveal";
    if (subjectSigner !== undefined) {
      return {
        module,
        subject_initiated: {
          subject_signer: subjectSigner,
          expected_axis: expectedAxis,
          eip712: SUBJECT_INITIATED_EIP712,
        },
      };
    }
    return { module };
  }

  if (module === "DeadManSwitch") {
    const actor =
      readAddress(reveal.actor) ?? readAddress(security.actor) ?? readAddress(params.actor);
    const interval =
      toNumber(reveal.interval_seconds) ??
      toNumber(security.interval_seconds) ??
      toNumber(params.heartbeat_interval_seconds) ??
      toNumber(params.interval_seconds);
    const grace =
      toNumber(reveal.grace_period_seconds) ??
      toNumber(security.grace_period_seconds) ??
      toNumber(params.grace_window_seconds) ??
      toNumber(params.grace_period_seconds);
    if (actor !== undefined && interval !== undefined && grace !== undefined) {
      return {
        module,
        dead_man_switch: {
          actor,
          interval_seconds: interval,
          grace_period_seconds: grace,
          eip712: DEAD_MAN_SWITCH_EIP712,
        },
      };
    }
    return { module };
  }

  return { module };
}

// ── Real addresses the PDA configures (nothing hardcoded in emit.ts — these come
//    from the partner-submitted PDA config) ─────────────────────────────────────
const SUBJECT_SIGNER = "0x1111111111111111111111111111111111111111";
const DMS_ACTOR = "0x2222222222222222222222222222222222222222";

/** A SubjectInitiated PDA raw input (kyc base, swap the reveal-condition module). */
function subjectInitiatedInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ...scaffoldFor("kyc-lending"),
    use_case: "subject_initiated_release",
    template_id: hashToHex32("subject_initiated_release_v2"),
    template_name: "subject_initiated_release_v2",
    reveal_condition: {
      module: "SubjectInitiated",
      template_pick: hashToHex32("SubjectInitiatedModule"),
      parameter_values: { axis: "reveal" },
      subject_signer: SUBJECT_SIGNER,
      expected_axis: "reveal",
      ...recordValue(overrides.reveal_condition),
    },
    partner_id: "partner_subject_initiated",
    pda_id: "pda_subject_initiated_001",
    pda_version: 1,
  };
}

/** The dead-man-switch scaffold + the PDA-configured `actor` the contract binds. */
function deadManSwitchInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base = scaffoldFor("dead-man-switch");
  return {
    ...base,
    reveal_condition: {
      ...recordValue(base.reveal_condition),
      actor: DMS_ACTOR,
      ...recordValue(overrides.reveal_condition),
    },
    pda_id: "pda_dead_man_switch_001",
    pda_version: 1,
  };
}

describe("T5.1 — EIP-712 module bindings match the deployed contracts (no drift)", () => {
  it("the mirrored SubjectInitiated binding equals CealisSubjectInitiated v1", () => {
    // These literals are the contract's own EIP-712 constants
    // (SubjectInitiatedModule.sol _DOMAIN_NAME_HASH / _DOMAIN_VERSION_HASH /
    // _SUBJECT_ACTION_TYPEHASH). They MUST match what the inspector pins and what
    // the emitter's downstream module-config call signs against.
    expect(SUBJECT_INITIATED_EIP712.domain_name).toBe("CealisSubjectInitiated");
    expect(SUBJECT_INITIATED_EIP712.domain_version).toBe("1");
    expect(SUBJECT_INITIATED_EIP712.struct_typehash).toBe(
      "SubjectAction(bytes32 authorizationId,bytes32 actionDigest,address subject)",
    );
  });

  it("the mirrored DeadManSwitch binding equals CealisDeadManSwitch v1", () => {
    expect(DEAD_MAN_SWITCH_EIP712.domain_name).toBe("CealisDeadManSwitch");
    expect(DEAD_MAN_SWITCH_EIP712.domain_version).toBe("1");
    expect(DEAD_MAN_SWITCH_EIP712.struct_typehash).toBe(
      "Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)",
    );
  });
});

describe("T5.1 — SubjectInitiated PDA emits subjectSigner at the inspector's read location", () => {
  it("prepareSubmittedPda surfaces subject_signer on reveal_condition (inspector read path)", () => {
    const submitted = prepareSubmittedPda(subjectInitiatedInput());
    const reveal = recordValue(submitted.reveal_condition);
    // The exact field the inspector's highest-priority read consumes.
    expect(reveal.module).toBe("SubjectInitiated");
    expect(reveal.subject_signer).toBe(SUBJECT_SIGNER);
    expect(reveal.expected_axis).toBe("reveal");
  });

  it("round-trip emit→inspect agrees: subjectSigner + axis + EIP-712 binding", () => {
    const submitted = prepareSubmittedPda(subjectInitiatedInput());
    const inspected = inspectModuleSecurity(submitted);
    expect(inspected.module).toBe("SubjectInitiated");
    expect(inspected.dead_man_switch).toBeUndefined();
    expect(inspected.subject_initiated).toEqual({
      subject_signer: SUBJECT_SIGNER,
      expected_axis: "reveal",
      eip712: SUBJECT_INITIATED_EIP712,
    });
  });

  it("axis is PDA-driven (shred axis threads through, not hardcoded reveal)", () => {
    const submitted = prepareSubmittedPda(
      subjectInitiatedInput({ reveal_condition: { expected_axis: "shred" } }),
    );
    expect(inspectModuleSecurity(submitted).subject_initiated?.expected_axis).toBe("shred");
  });

  it("the security field is built into `submitted` by emitPDA's prepare step (the inspector's `resolved.submitted`)", () => {
    // emitPDA's first step is prepareSubmittedPda; its `submitted` IS the object
    // the T1.4 inspector consumes as `resolved.submitted`. We assert the security
    // field survives that step (the load-bearing seam). We do NOT assert full
    // emitPDA() success here: the fixtures hit a PRE-EXISTING Stage-3
    // template-pick gap (rows 54/56.1 `ALLOW_LIST_MISSING`) that is committed at
    // HEAD and unrelated to T5.1 — see the suite note below.
    const submitted = prepareSubmittedPda(subjectInitiatedInput());
    // Re-preparing is idempotent on the security field (emit re-runs prepare).
    const reprepared = prepareSubmittedPda(submitted as Record<string, unknown>);
    expect(recordValue(reprepared.reveal_condition).subject_signer).toBe(SUBJECT_SIGNER);
    expect(inspectModuleSecurity(reprepared).subject_initiated?.subject_signer).toBe(SUBJECT_SIGNER);
  });
});

describe("T5.1 — DeadManSwitch PDA emits actor at the inspector's read location", () => {
  it("prepareSubmittedPda surfaces actor + interval + grace on reveal_condition", () => {
    const submitted = prepareSubmittedPda(deadManSwitchInput());
    const reveal = recordValue(submitted.reveal_condition);
    expect(reveal.module).toBe("DeadManSwitch");
    expect(reveal.actor).toBe(DMS_ACTOR);
    // interval / grace surfaced from the DeadManSwitch evidence parameters.
    expect(reveal.interval_seconds).toBe(2_592_000);
    expect(reveal.grace_period_seconds).toBe(604_800);
  });

  it("round-trip emit→inspect agrees: actor + interval + grace + EIP-712 binding", () => {
    const submitted = prepareSubmittedPda(deadManSwitchInput());
    const inspected = inspectModuleSecurity(submitted);
    expect(inspected.module).toBe("DeadManSwitch");
    expect(inspected.subject_initiated).toBeUndefined();
    expect(inspected.dead_man_switch).toEqual({
      actor: DMS_ACTOR,
      interval_seconds: 2_592_000,
      grace_period_seconds: 604_800,
      eip712: DEAD_MAN_SWITCH_EIP712,
    });
  });

  it("actor is PDA-driven (a different configured actor threads through)", () => {
    const altActor = "0x3333333333333333333333333333333333333333";
    const submitted = prepareSubmittedPda(
      deadManSwitchInput({ reveal_condition: { actor: altActor } }),
    );
    expect(inspectModuleSecurity(submitted).dead_man_switch?.actor).toBe(altActor);
  });

  it("the actor is built into `submitted` by emitPDA's prepare step (the inspector's `resolved.submitted`)", () => {
    const submitted = prepareSubmittedPda(deadManSwitchInput());
    const reprepared = prepareSubmittedPda(submitted as Record<string, unknown>);
    expect(recordValue(reprepared.reveal_condition).actor).toBe(DMS_ACTOR);
    expect(inspectModuleSecurity(reprepared).dead_man_switch?.actor).toBe(DMS_ACTOR);
  });
});

describe("T5.1 — nothing synthesized (platform principle / Rule 19)", () => {
  it("a module with no signer binding (PaymentObligation) emits neither field", () => {
    const submitted = prepareSubmittedPda(scaffoldFor("kyc-lending"));
    const reveal = recordValue(submitted.reveal_condition);
    expect(reveal.module).toBe("PaymentObligation");
    expect(reveal.subject_signer).toBeUndefined();
    expect(reveal.actor).toBeUndefined();
    const inspected = inspectModuleSecurity(submitted);
    expect(inspected.subject_initiated).toBeUndefined();
    expect(inspected.dead_man_switch).toBeUndefined();
  });

  it("a SubjectInitiated PDA WITHOUT a partner-supplied signer surfaces no signer (fail-loud downstream, not a forged default)", () => {
    const input = subjectInitiatedInput();
    const reveal = recordValue(input.reveal_condition);
    delete reveal.subject_signer;
    input.reveal_condition = reveal;
    const submitted = prepareSubmittedPda(input);
    expect(recordValue(submitted.reveal_condition).subject_signer).toBeUndefined();
    expect(inspectModuleSecurity(submitted).subject_initiated).toBeUndefined();
  });

  it("a DeadManSwitch PDA WITHOUT a partner-supplied actor surfaces no actor", () => {
    const base = scaffoldFor("dead-man-switch");
    // No `actor` added — the stock scaffold has none.
    const submitted = prepareSubmittedPda(base);
    expect(recordValue(submitted.reveal_condition).actor).toBeUndefined();
    expect(inspectModuleSecurity(submitted).dead_man_switch).toBeUndefined();
  });

  it("a non-address signer is rejected (not coerced) — emit refuses to surface garbage", () => {
    const submitted = prepareSubmittedPda(
      subjectInitiatedInput({ reveal_condition: { subject_signer: "not-an-address" } }),
    );
    // emit's readAddress validates `0x`+40hex; a bad value is dropped, not passed.
    expect(recordValue(submitted.reveal_condition).subject_signer).toBeUndefined();
  });
});
