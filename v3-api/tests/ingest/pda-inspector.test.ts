// PdaInspector tests (T1.4).
//
// Proves, with an injected FAKE `PdaConfigSource` (no Postgres / no full
// configurator emit pipeline — pure unit test, runs in CI without infra):
//
//   1. The inspector maps a resolved PDA config onto the extended ingest
//      inspection: pda_root / digests / g3_choice / g4_phase / trust_tier /
//      retention / challenge windows / shred authority all come from the PDA,
//      none synthesized.
//   2. ACCESS-STRUCTURE PROFILE is correctly derived from the conditional-
//      recipient policy across archetypes:
//        - kyc-lending (PaymentObligation, no conditional recipients) → FIXED_ONLY
//        - dead-man-switch (n=2, k=1)                                  → RECIPIENT_K_OF_N
//        - a single-fixed-recipient PDA (n=1, k=1)                     → RECIPIENT_1_OF_1
//   3. THE NEW SECURITY PDA FIELDS the 2026-06-02 contracts added are surfaced:
//        - SubjectInitiated → subject_signer + EIP-712 `CealisSubjectInitiated`
//        - DeadManSwitch    → actor + interval/grace + `CealisDeadManSwitch`
//      read straight from the PDA's reveal-condition module config (forward-
//      compatible with T5.1's emission), with the module's own EIP-712 typehash.
//   4. PLATFORM PRINCIPLE: the same inspector drives every archetype with no
//      code change — the flow is whatever the PDA selects.
//   5. The Postgres source's active-agreement gate: a missing active agreement
//      throws `PdaNotFoundError`; an active row resolves the artifact. Asserted
//      against an injected FAKE `Sql` (logic-level, no real DB) + a live layer
//      that SKIPs cleanly when no V3 Postgres URL is set.
//
// The mapping is the load-bearing core; the configurator value-helpers
// (`hashToBytes32` / `hexToBytes32`) build REAL Bytes32 inspection fields and
// `prepareSubmittedPda` builds REAL submitted PDAs from the app-a fixture
// scaffolds, so the read exercises the genuine configurator output shape.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres from "postgres";
import type { Sql } from "postgres";

import {
  hashToBytes32,
  hexToBytes32,
  prepareSubmittedPda,
  type PartnerReadableInspection,
} from "@cealis/v3-configurator";

import {
  createPdaInspector,
  deriveAccessStructureProfile,
  deriveModuleSecurity,
  deriveOperationalClass,
  mapResolvedPdaToInspection,
  PdaNotFoundError,
  PostgresPdaConfigSource,
  SUBJECT_INITIATED_EIP712,
  DEAD_MAN_SWITCH_EIP712,
  type PdaArtifactLoader,
  type PdaConfigSource,
  type ResolvedPdaConfig,
} from "../../src/ingest/pda-inspector.js";
import type { OperationalClass } from "../../src/types/index.js";

// ── Real-inspection builders (genuine configurator Bytes32 fields) ──────────────

interface InspectionOverrides {
  readonly partner_id?: string;
  readonly pda_id?: string;
  readonly pda_version?: bigint;
  readonly g3_choice?: "dcipher" | "drand";
  readonly g4_phase?: 1 | 2;
  readonly trust_tier?: "A" | "B" | "C";
  readonly conditional?: { readonly n: number; readonly k: number };
  readonly retention_seconds?: bigint;
  readonly reveal_challenge_seconds?: bigint;
  readonly shred_challenge_seconds?: bigint;
  readonly shred_authority?: PartnerReadableInspection["shred_authority"];
  readonly legal_effect_expected?: boolean;
}

/**
 * Build a REAL `PartnerReadableInspection` (every Bytes32 produced by the
 * configurator's own `hashToBytes32` / `hexToBytes32`) for a given PDA shape.
 * Only the fields the mapper reads vary by override; the rest are valid
 * placeholders so the object is a structurally-real inspection.
 */
function buildInspection(o: InspectionOverrides = {}): PartnerReadableInspection {
  const conditional = o.conditional ?? { n: 0, k: 0 };
  return {
    partner_id: hashToBytes32(o.partner_id ?? "partner:test"),
    pda_id: hexToBytes32(`0x${"ab".repeat(32)}`),
    pda_version: o.pda_version ?? 1n,
    pda_root: hashToBytes32(`pda-root:${o.pda_id ?? "test"}`),
    template_id: hashToBytes32("template:test"),
    template_digest: hashToBytes32("template-digest:test"),
    schema_digest: hashToBytes32(`schema:${o.pda_id ?? "test"}`),
    schema_summary_human_readable: "2 schema fields",
    reveal_condition_summary: "PaymentObligation P",
    shred_condition_summary: "P with mandatory guardrail",
    trust_tier: o.trust_tier ?? "A",
    oracle_refs: [
      { oracle_id: hashToBytes32("chain-native"), tier: o.trust_tier ?? "A", schema_ref: hashToBytes32("schema:default") },
    ],
    g3_choice: o.g3_choice ?? "dcipher",
    g4_phase: o.g4_phase ?? 2,
    recipients_summary: [{ role_tag: "RECIPIENT", delivery_mode: "PASSKEY_ACCOUNT", schema_selector: "$" }],
    conditional_recipient_policy_summary: {
      n: conditional.n,
      k: conditional.k,
      role_summary: conditional.n > 0 ? ["BENEFICIARY"] : [],
      updatable: false,
    },
    sd_audit_diff_non_escrow_only: [],
    retention_windows: {
      retention_seconds: o.retention_seconds ?? 94_608_000n,
      minimum_shred_latency_seconds: 0n,
    },
    challenge_windows: {
      reveal_seconds: o.reveal_challenge_seconds ?? 0n,
      shred_seconds: o.shred_challenge_seconds ?? 0n,
    },
    shred_authority: o.shred_authority ?? "Subject",
    shred_condition: { mode: "P", spec_digest: hashToBytes32("shred-spec"), mandatory_guardrail_present: true },
    legal_flags_art9_qes_jurisdiction: {
      legal_effect_expected: o.legal_effect_expected ?? false,
      art_9_scoped: false,
      art_9_basis_id: 0,
      qes_subject_required: false,
      qtsp_provider_ref: hashToBytes32("qtsp:none"),
      applicable_jurisdiction: hashToBytes32("jurisdiction:DE"),
    },
    class_table_classification_per_surface: new Map(),
    defaults_applied_with_override_flags: [],
    validation_report_digest: hashToBytes32("validation"),
    simulation_report_digest: hashToBytes32("simulation"),
    ipfs_cids: [],
    on_chain_tx_refs: [],
  };
}

function resolved(
  inspection: PartnerReadableInspection,
  submitted: Record<string, unknown>,
  operational_class: OperationalClass,
  extra: Partial<ResolvedPdaConfig> = {},
): ResolvedPdaConfig {
  return {
    inspection,
    submitted,
    operational_class,
    partner_ready: true,
    ...extra,
  };
}

/** A fake source returning a fixed resolved config (the unit-test seam). */
function fakeSource(config: ResolvedPdaConfig): PdaConfigSource {
  return { loadActivePda: () => Promise.resolve(config) };
}

const ADDR_SUBJECT = "0x1111111111111111111111111111111111111111";
const ADDR_ACTOR = "0x2222222222222222222222222222222222222222";

/**
 * Merge module-security fields onto a real `prepareSubmittedPda` output's
 * reveal_condition. The current configurator (`revealConditionFor`, emit.ts)
 * RECONSTRUCTS reveal_condition from scratch and does NOT yet carry the
 * subjectSigner / DMS-actor fields — that emission is T5.1's job, and T5.1
 * depends on this T1.4 surface. This helper simulates T5.1's emission so the
 * inspector's READ is exercised against the genuine submitted-PDA shape PLUS the
 * forward-compatible security location. The base submitted PDA stays real.
 */
function withModuleSecurity(
  submitted: Record<string, unknown>,
  security: Record<string, unknown>,
): Record<string, unknown> {
  const reveal =
    typeof submitted.reveal_condition === "object" && submitted.reveal_condition !== null
      ? (submitted.reveal_condition as Record<string, unknown>)
      : {};
  return { ...submitted, reveal_condition: { ...reveal, ...security } };
}

// ── Mapping + archetype tests ──────────────────────────────────────────────────

describe("deriveAccessStructureProfile", () => {
  it("n=0 → FIXED_ONLY (3-of-3 over {Lit, G3, G4})", () => {
    expect(deriveAccessStructureProfile({ n: 0, k: 0 })).toEqual({ kind: "FIXED_ONLY" });
  });

  it("n=1, k=1 → RECIPIENT_1_OF_1", () => {
    expect(deriveAccessStructureProfile({ n: 1, k: 1 })).toEqual({ kind: "RECIPIENT_1_OF_1" });
  });

  it("n=2, k=1 → RECIPIENT_K_OF_N{n:2,k:1}", () => {
    expect(deriveAccessStructureProfile({ n: 2, k: 1 })).toEqual({
      kind: "RECIPIENT_K_OF_N",
      n_conditional: 2,
      k_conditional: 1,
    });
  });

  it("clamps a degenerate k (0 or > n) into [1, n]", () => {
    expect(deriveAccessStructureProfile({ n: 3, k: 0 })).toEqual({
      kind: "RECIPIENT_K_OF_N",
      n_conditional: 3,
      k_conditional: 1,
    });
    expect(deriveAccessStructureProfile({ n: 3, k: 9 })).toEqual({
      kind: "RECIPIENT_K_OF_N",
      n_conditional: 3,
      k_conditional: 3,
    });
  });
});

describe("deriveOperationalClass", () => {
  it("legal_effect_expected → legal_effect", () => {
    expect(deriveOperationalClass({ legal_effect_expected: true, trust_tier: "tier_a" })).toBe("legal_effect");
  });
  it("tier_c → regulated", () => {
    expect(deriveOperationalClass({ legal_effect_expected: false, trust_tier: "tier_c" })).toBe("regulated");
  });
  it("otherwise → b2b_partner", () => {
    expect(deriveOperationalClass({ legal_effect_expected: false, trust_tier: "tier_b" })).toBe("b2b_partner");
  });
});

describe("PdaInspector — archetype mapping (real fixture submitted PDAs)", () => {
  it("kyc-lending (PaymentObligation, no conditional recipients) → FIXED_ONLY", async () => {
    // REAL submitted PDA from the app-a kyc-lending scaffold shape.
    const submitted = prepareSubmittedPda({
      use_case: "kyc-lending",
      archetype: "enforcement",
      template_id: hexToBytesHex("kyc_lending_payment_default_v2"),
      template_name: "kyc_lending_payment_default_v2",
      g3_choice: "dcipher",
      g4_phase: 2,
      trust_tier: "A",
      reveal_condition: { module: "PaymentObligation", parameter_values: { default_after_seconds: 0 } },
      shred_condition: { mode: "P", spec_hash: hexToBytesHex("kyc:shred"), mandatory_guardrail_present: true },
      legal_effect_expected: true,
      partner_id: "partner_kyc_lending",
      pda_id: "pda_kyc_1",
      pda_version: 1,
      retention_seconds: 94_608_000,
    });
    const inspection = buildInspection({
      partner_id: "partner_kyc_lending",
      g3_choice: "dcipher",
      g4_phase: 2,
      trust_tier: "A",
      conditional: { n: 0, k: 0 },
      legal_effect_expected: true,
      retention_seconds: 94_608_000n,
    });

    const inspectPda = createPdaInspector(fakeSource(resolved(inspection, submitted, "legal_effect")));
    const out = await inspectPda({ partner_id: "partner_kyc_lending", pda_id: "pda_kyc_1", pda_version: "1" });

    // Everything PDA-derived (platform principle: nothing hardcoded).
    expect(out.g3_choice).toBe("dcipher");
    expect(out.g4_phase).toBe(2);
    expect(out.trust_tier).toBe("tier_a"); // mapped from configurator "A"
    expect(out.operational_class).toBe("legal_effect");
    expect(out.legal_effect_expected).toBe(true);
    expect(out.retention_seconds).toBe(94_608_000n);
    expect(out.pda_version).toBe("1");
    // Access structure: no conditional recipients → FIXED_ONLY (3-of-3).
    expect(out.access_structure_profile).toEqual({ kind: "FIXED_ONLY" });
    // PaymentObligation has no EIP-712 signer binding — module only, no security sub-config.
    expect(out.module_security).toEqual({ module: "PaymentObligation" });
    // pda_root / schema_digest are 0x-hex (Bytes32 → Hex32).
    expect(out.pda_root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(out.schema_digest).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("dead-man-switch (n=2, k=1, DMS actor) → RECIPIENT_K_OF_N + CealisDeadManSwitch security", async () => {
    // REAL submitted PDA from the app-a dead-man-switch scaffold + the (T5.1-
    // forward) actor/interval/grace the merged DeadManSwitchModule binds.
    const submitted = withModuleSecurity(
      prepareSubmittedPda({
        use_case: "dead_man_switch",
        archetype: "conditional_reveal_liveness",
        template_id: hexToBytesHex("dead_man_switch_heartbeat_release_v2"),
        template_name: "dead_man_switch_heartbeat_release_v2",
        g3_choice: "drand",
        g4_phase: 2,
        trust_tier: "B",
        reveal_condition: { module: "DeadManSwitch" },
        shred_condition: { mode: "P", spec_hash: hexToBytesHex("dms:shred"), mandatory_guardrail_present: true },
        conditional_recipients: { n: 2, k: 1, role_tags: ["BENEFICIARY"], updatable: true },
        shred_authority: "Subject",
        legal_effect_expected: false,
        partner_id: "partner_dead_man_switch",
        pda_id: "pda_dms_1",
        pda_version: 3,
        retention_seconds: 315_360_000,
      }),
      {
        actor: ADDR_ACTOR,
        evidence_parameters: {
          heartbeat_interval_seconds: 2_592_000,
          grace_window_seconds: 604_800,
        },
      },
    );
    const inspection = buildInspection({
      partner_id: "partner_dead_man_switch",
      pda_version: 3n,
      g3_choice: "drand",
      g4_phase: 2,
      trust_tier: "B",
      conditional: { n: 2, k: 1 },
      shred_authority: "Subject",
      retention_seconds: 315_360_000n,
    });

    const inspectPda = createPdaInspector(fakeSource(resolved(inspection, submitted, "b2b_partner")));
    const out = await inspectPda({ partner_id: "partner_dead_man_switch", pda_id: "pda_dms_1", pda_version: "3" });

    expect(out.g3_choice).toBe("drand");
    expect(out.trust_tier).toBe("tier_b"); // mapped from configurator "B"
    expect(out.shred_authority).toBe("subject"); // lowercased from "Subject"
    expect(out.access_structure_profile).toEqual({
      kind: "RECIPIENT_K_OF_N",
      n_conditional: 2,
      k_conditional: 1,
    });
    // The NEW DeadManSwitch security PDA config — actor + interval/grace + EIP-712.
    expect(out.module_security.module).toBe("DeadManSwitch");
    expect(out.module_security.dead_man_switch).toEqual({
      actor: ADDR_ACTOR,
      interval_seconds: 2_592_000,
      grace_period_seconds: 604_800,
      eip712: DEAD_MAN_SWITCH_EIP712,
    });
    expect(out.module_security.dead_man_switch?.eip712.domain_name).toBe("CealisDeadManSwitch");
    expect(out.module_security.subject_initiated).toBeUndefined();
  });

  it("subject-initiated (n=1, k=1, subjectSigner) → RECIPIENT_1_OF_1 + CealisSubjectInitiated security", async () => {
    const submitted = withModuleSecurity(
      prepareSubmittedPda({
        use_case: "subject_initiated_release",
        archetype: "conditional_reveal",
        template_id: hexToBytesHex("subject_initiated_v1"),
        template_name: "subject_initiated_v1",
        g3_choice: "dcipher",
        g4_phase: 2,
        trust_tier: "A",
        reveal_condition: { module: "SubjectInitiated" },
        shred_condition: { mode: "P", spec_hash: hexToBytesHex("si:shred"), mandatory_guardrail_present: true },
        conditional_recipients: { n: 1, k: 1, role_tags: ["SELF"], updatable: false },
        partner_id: "partner_subject_initiated",
        pda_id: "pda_si_1",
        pda_version: 1,
        retention_seconds: 31_536_000,
      }),
      { subject_signer: ADDR_SUBJECT, expected_axis: "reveal" },
    );
    const inspection = buildInspection({
      partner_id: "partner_subject_initiated",
      g3_choice: "dcipher",
      g4_phase: 2,
      trust_tier: "A",
      conditional: { n: 1, k: 1 },
      retention_seconds: 31_536_000n,
    });

    const inspectPda = createPdaInspector(fakeSource(resolved(inspection, submitted, "b2b_partner")));
    const out = await inspectPda({ partner_id: "partner_subject_initiated", pda_id: "pda_si_1", pda_version: "1" });

    expect(out.access_structure_profile).toEqual({ kind: "RECIPIENT_1_OF_1" });
    expect(out.module_security.module).toBe("SubjectInitiated");
    expect(out.module_security.subject_initiated).toEqual({
      subject_signer: ADDR_SUBJECT,
      expected_axis: "reveal",
      eip712: SUBJECT_INITIATED_EIP712,
    });
    expect(out.module_security.subject_initiated?.eip712.domain_name).toBe("CealisSubjectInitiated");
    expect(out.module_security.subject_initiated?.eip712.struct_typehash).toContain("SubjectAction(");
    expect(out.module_security.dead_man_switch).toBeUndefined();
  });
});

describe("deriveModuleSecurity — fail-safe (no synthesized signer)", () => {
  it("SubjectInitiated without a configured signer → no sub-config (Rule 19: never fabricate)", () => {
    const security = deriveModuleSecurity({ reveal_condition: { module: "SubjectInitiated" } });
    expect(security).toEqual({ module: "SubjectInitiated" });
    expect(security.subject_initiated).toBeUndefined();
  });

  it("DeadManSwitch missing interval/grace → no sub-config (all of actor+interval+grace required)", () => {
    const security = deriveModuleSecurity({
      reveal_condition: { module: "DeadManSwitch", actor: ADDR_ACTOR },
    });
    expect(security).toEqual({ module: "DeadManSwitch" });
    expect(security.dead_man_switch).toBeUndefined();
  });

  it("rejects a non-address signer value (only valid 0x-addresses surface)", () => {
    const security = deriveModuleSecurity({
      reveal_condition: { module: "SubjectInitiated", subject_signer: "not-an-address" },
    });
    expect(security.subject_initiated).toBeUndefined();
  });

  it("reads the security config from a nested module_security record too", () => {
    const security = deriveModuleSecurity({
      reveal_condition: { module: "SubjectInitiated", module_security: { subject_signer: ADDR_SUBJECT, expected_axis: "shred" } },
    });
    expect(security.subject_initiated?.subject_signer).toBe(ADDR_SUBJECT);
    expect(security.subject_initiated?.expected_axis).toBe("shred");
  });
});

describe("mapResolvedPdaToInspection — assignability to PdaInspectionForIngest", () => {
  it("the extended inspection is a superset usable wherever the narrow surface is expected", () => {
    const inspection = buildInspection({ conditional: { n: 0, k: 0 } });
    const submitted = prepareSubmittedPda({
      partner_id: "p",
      pda_id: "pda_x",
      pda_version: 1,
      template_id: hexToBytesHex("t"),
      retention_seconds: 1000,
      reveal_condition: { module: "PaymentObligation" },
    });
    const out = mapResolvedPdaToInspection(resolved(inspection, submitted, "b2b_partner", { retention_policy_id: "obligation_plus_3y" }));
    // Narrow-surface fields all present + typed.
    expect(out.pda_id).toMatch(/^0x[0-9a-f]{64}$/);
    expect(out.partner_id).toMatch(/^0x[0-9a-f]{64}$/);
    expect(out.retention_policy_id).toBe("obligation_plus_3y");
    expect(typeof out.partner_ready).toBe("boolean");
    expect(out.reveal_challenge_window_seconds).toBe(0);
  });
});

// ── PostgresPdaConfigSource — active-agreement gate ─────────────────────────────

/** Minimal tagged-template Sql double returning a programmable row set. */
function fakeSql(rowsToReturn: unknown[]): { sql: Sql; calls: { values: unknown[] }[] } {
  const calls: { values: unknown[] }[] = [];
  const tag = (_strings: TemplateStringsArray, ...values: unknown[]) => {
    calls.push({ values });
    return Promise.resolve(rowsToReturn);
  };
  return { sql: tag as unknown as Sql, calls };
}

function fakeArtifactLoader(inspection: PartnerReadableInspection, submitted: Record<string, unknown>): PdaArtifactLoader {
  return {
    load: () => Promise.resolve({ inspection, submitted, retention_policy_id: "obligation_plus_3y" }),
  };
}

describe("PostgresPdaConfigSource (logic, fake Sql)", () => {
  it("throws PdaNotFoundError when no active agreement row exists", async () => {
    const { sql } = fakeSql([]); // no active agreement
    const source = new PostgresPdaConfigSource({
      sql,
      artifactLoader: fakeArtifactLoader(buildInspection(), {}),
    });
    await expect(
      source.loadActivePda({ partner_id: "p", pda_id: "pda_missing", pda_version: "1" }),
    ).rejects.toBeInstanceOf(PdaNotFoundError);
  });

  it("resolves the artifact + derives operational class when an active agreement exists", async () => {
    const submitted = prepareSubmittedPda({
      partner_id: "p",
      pda_id: "pda_ok",
      pda_version: 1,
      template_id: hexToBytesHex("t"),
      retention_seconds: 1000,
      reveal_condition: { module: "PaymentObligation" },
    });
    const inspection = buildInspection({ legal_effect_expected: true, trust_tier: "A" });
    const { sql, calls } = fakeSql([{ pda_id: "pda_ok" }]);
    const source = new PostgresPdaConfigSource({ sql, artifactLoader: fakeArtifactLoader(inspection, submitted) });

    const config = await source.loadActivePda({ partner_id: "p", pda_id: "pda_ok", pda_version: "1" });
    expect(config.operational_class).toBe("legal_effect"); // derived from legal_effect_expected
    expect(config.retention_policy_id).toBe("obligation_plus_3y");
    expect(config.partner_ready).toBe(true);
    // The active-agreement query was bound with the partner_id / pda_id / 'active'.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.values).toContain("p");
    expect(calls[0]?.values).toContain("pda_ok");
    expect(calls[0]?.values).toContain("active");
  });
});

// ── Live layer (opt-in; SKIPs without a V3 Postgres URL) ────────────────────────

const TEST_PG_URL = process.env["V3_TEST_PG_URL"] ?? process.env["CEALIS_V3_DATABASE_URL"];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

describeIfPg("PostgresPdaConfigSource (live Postgres)", () => {
  let sql: Sql;

  beforeAll(() => {
    sql = postgres(TEST_PG_URL as string);
  });

  afterAll(async () => {
    if (sql) await sql.end({ timeout: 5 });
  });

  it("returns PdaNotFoundError for a partner with no active agreement (real DB)", async () => {
    const source = new PostgresPdaConfigSource({
      sql,
      artifactLoader: fakeArtifactLoader(buildInspection(), {}),
    });
    await expect(
      source.loadActivePda({
        partner_id: "00000000-0000-0000-0000-000000000000",
        pda_id: "pda_definitely_absent",
        pda_version: "1",
      }),
    ).rejects.toBeInstanceOf(PdaNotFoundError);
  });
});

/** Build a valid `0x…64` from a label (the scaffolds pass 0x-hex template ids). */
function hexToBytesHex(label: string): string {
  let out = "";
  for (let i = 0; i < 64; i++) {
    const code = label.charCodeAt(i % label.length) + i * 13;
    out += (code & 0xf).toString(16);
  }
  return `0x${out}`;
}
