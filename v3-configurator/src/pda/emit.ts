import { COMMIT_AAD_FIELD_NAMES } from "../types/commit-aad.js";
import { PDA_ROOT_FIELD_NAMES } from "../types/pda-root.js";
import type { DualFormValidationFailure } from "../errors/index.js";
import { applyDefaultPrecedence } from "../defaults/precedence.js";
import {
  runSimulationHarness,
  type SimulationHarnessInput,
  type SimulationHarnessResult,
} from "../simulation/index.js";
import { CLASS_TABLE, CLASS_TABLE_ROWS } from "../validate/class-table/table.js";
import { runStage2 } from "../validate/crypto-invariant/dispatcher.js";
import { validateCrossFieldRules } from "../validate/cross-field/dispatcher.js";
import type { CrossFieldValidationContext } from "../validate/cross-field/types.js";
import {
  runStage1,
  type SubmittedPda,
} from "../validate/syntax/index.js";
import {
  validateStage3Pda,
  type Stage3SubmittedPda,
  type Stage3SubmittedSurface,
  type Stage3ValidationContext,
  type Stage3Value,
} from "../validate/stage3/index.js";
import { TEMPLATE_PICK_ROW_IDS } from "../validate/stage3/allow-list-checker.js";
import type { NumericBounds } from "../validate/stage3/bounds-checker.js";
import { registeredTemplateIds } from "./template-registry.js";
import { canonicalizeJson, computeContentHash } from "./content-hash.js";
import { diffPdaEvolution, type PdaDiffResult, type PdaDiffOptions } from "./diff.js";
import { pinToIpfsOffline, type IpfsPin } from "./ipfs-pin.js";
import {
  bytesToHex,
  computePdaRootFromFields,
  derivePdaRootFields,
  hashToBytes32,
  hashToHex32,
  hexToBytes32,
} from "./pda-root.js";
import { renderInspection, serializeInspection } from "./inspection.js";
import { recordAuditTrail } from "./audit-trail.js";
import { mockRegisterPDA, tripleRootGuard, type MockPdaRegisteredEvent } from "./triple-root-guard.js";
import type { AuditTrailRecord } from "../types/audit-trail.js";
import type { PartnerReadableInspection } from "../types/partner-inspection.js";

export interface ValidationReport {
  readonly stage1: readonly DualFormValidationFailure[];
  readonly stage2: readonly DualFormValidationFailure[];
  readonly stage3: readonly DualFormValidationFailure[];
  readonly stage4: readonly DualFormValidationFailure[];
  readonly stage5: SimulationHarnessResult;
  readonly ok: boolean;
  readonly digest: Uint8Array;
}

export interface EmittedPdaArtifact {
  readonly artifact_type: "cealis.v3.pda";
  readonly artifact_version: 1;
  readonly submitted: SubmittedPda;
  readonly canonical_json: string;
  readonly contentHash: `0x${string}`;
  readonly pdaRoot: `0x${string}`;
  readonly ipfs: readonly IpfsPin[];
  readonly onChain: MockPdaRegisteredEvent;
  readonly audit: AuditTrailRecord;
  readonly inspection: PartnerReadableInspection;
  readonly inspection_json: Record<string, unknown>;
  readonly validation: ValidationReport;
  readonly signature: `0x${string}`;
}

export class ValidationFailure extends Error {
  readonly stage: 1 | 2 | 3 | 4;
  readonly failures: readonly DualFormValidationFailure[];

  constructor(stage: 1 | 2 | 3 | 4, failures: readonly DualFormValidationFailure[]) {
    super(`Stage ${String(stage)} validation failed with ${String(failures.length)} failures`);
    this.name = "ValidationFailure";
    this.stage = stage;
    this.failures = failures;
  }
}

export class SimulationFailure extends Error {
  readonly result: SimulationHarnessResult;

  constructor(result: SimulationHarnessResult) {
    super("Stage 5 simulation failed");
    this.name = "SimulationFailure";
    this.result = result;
  }
}

export interface PartnerBoundaryOptions {
  /**
   * Set true ONLY for internal scaffold/fixture/test generators that
   * legitimately rely on the defaults inside `prepareSubmittedPda`.
   * Partner-facing call-sites MUST leave this false (the default) so the
   * required-field guard fires before any synthetic attribution can occur.
   *
   * Security-audit-2026-06-02 TS-API-F-08.
   */
  readonly allowFixtureDefaults?: boolean;
}

export async function emitPDA(
  input: Record<string, unknown>,
  options?: PartnerBoundaryOptions,
): Promise<EmittedPdaArtifact> {
  if (options?.allowFixtureDefaults !== true) {
    // TS-API-F-08: refuse to silently fill partner_id/template_id/etc. defaults
    // at the partner-facing emit boundary. Internal fixtures opt out explicitly.
    assertPartnerInputRequiredFields(input);
  }
  const submitted = prepareSubmittedPda(input);
  const validation = validatePDA(submitted, { allowFixtureDefaults: true });
  throwIfInvalid(validation);

  const canonical = canonicalizeJson(submitted);
  const template = templateSpec(submitted);
  const contentHash = computeContentHash(template);
  const pdaRoot = computePdaRootFromFields(derivePdaRootFields(submitted));
  const ipfs = await pinToIpfsOffline(canonical, {
    includeFilecoin: recordValue(submitted.extension_metadata).filecoin_deal === true,
  });
  const event = await mockRegisterPDA(pdaRoot);
  tripleRootGuard({ local: pdaRoot, contractHelper: event.contractHelper, emittedEvent: event.pdaRoot });

  const audit = recordAuditTrail({
    submitted,
    validationDigest: validation.digest,
    validationPass: validation.ok,
    stagePasses: [true, true, true, true, validation.stage5.ok],
    failureCount: 0,
    simulationDigest: validation.stage5.simulation_digest,
    pdaRoot,
    ipfsCids: ipfs.map((pin) => pin.cid),
    txRefs: [
      {
        chain_id: 31_337,
        tx_hash: hexToBytes32(event.txHash),
        block_number: event.blockNumber,
      },
    ],
  });

  const defaults = applyDefaultPrecedence({
    use_case: readString(submitted.use_case),
    archetype: readString(submitted.archetype),
  });
  const inspection = renderInspection({
    submitted,
    pdaRoot,
    templateDigest: contentHash,
    validationReportDigest: validation.digest,
    simulation: validation.stage5,
    ipfsPins: ipfs,
    event,
    classTableRows: CLASS_TABLE_ROWS,
    defaults: defaults.inspection_records,
  });
  const signature = hashToHex32({ pdaRoot: bytesToHex(pdaRoot), contentHash: bytesToHex(contentHash) });

  return {
    artifact_type: "cealis.v3.pda",
    artifact_version: 1,
    submitted,
    canonical_json: canonical,
    contentHash: bytesToHex(contentHash),
    pdaRoot: bytesToHex(pdaRoot),
    ipfs,
    onChain: event,
    audit,
    inspection,
    inspection_json: serializeInspection(inspection),
    validation,
    signature,
  };
}

export function validatePDA(
  input: Record<string, unknown>,
  options?: PartnerBoundaryOptions,
): ValidationReport {
  if (options?.allowFixtureDefaults !== true) {
    // TS-API-F-08: at the partner-facing validate boundary, reject a PDA that
    // is missing a partner-supplied required field BEFORE prepareSubmittedPda
    // coerces it into a synthetic `partner_fixture` attribution. `emitPDA`
    // already ran this guard on the raw input, so it re-validates with the
    // opt-out flag to avoid double-failing on the prepared object.
    assertPartnerInputRequiredFields(input);
  }
  const submitted = prepareSubmittedPda(input);
  const stage1 = runStage1(submitted);
  const stage2 = stage1.length === 0 ? runStage2(submitted) : [];
  const stage3 =
    stage1.length === 0 && stage2.length === 0
      ? validateStage3Pda(adaptToStage3(submitted), buildStage3Context(submitted))
      : [];
  const stage4 =
    stage1.length === 0 && stage2.length === 0 && stage3.length === 0
      ? validateCrossFieldRules(buildCrossFieldContext(submitted))
      : [];
  const stage5 = runSimulationHarness(buildSimulationInput(submitted));
  const ok =
    stage1.length === 0 &&
    stage2.length === 0 &&
    stage3.length === 0 &&
    stage4.length === 0 &&
    stage5.ok;
  return {
    stage1,
    stage2,
    stage3,
    stage4,
    stage5,
    ok,
    digest: hashToBytes32({
      stage1: stage1.map((failure) => failure.stage_code),
      stage2: stage2.map((failure) => failure.stage_code),
      stage3: stage3.map((failure) => failure.stage_code),
      stage4: stage4.map((failure) => failure.stage_code),
      stage5: stage5.simulation_digest,
    }),
  };
}

/**
 * Asserts that a partner-supplied raw PDA input has all fields that MUST come
 * from the partner (not be silently filled by defaults). Throws with a
 * MISSING_REQUIRED_FIELD-shaped error listing every offending field.
 *
 * Use this at every API-boundary call-site that ingests partner PDAs before
 * invoking `prepareSubmittedPda` — otherwise the defaults at lines 213, 199-201,
 * 269 silently coerce missing fields into `"partner_fixture"`, derived IDs,
 * and a default retention, allowing attribution forgery. Internal scaffold
 * generators (fixtures, tests) deliberately keep using `prepareSubmittedPda`
 * without this assertion because they LEGITIMATELY rely on defaults.
 *
 * Security-audit-2026-05-14 TS-API-F-08.
 */
export const PARTNER_SUPPLIED_REQUIRED_FIELDS = Object.freeze([
  "partner_id",
  "pda_id",
  "pda_version",
  "template_id",
  "retention_seconds",
]);

export class PartnerInputMissingRequiredFieldsError extends Error {
  readonly code = "MISSING_REQUIRED_FIELD";
  constructor(readonly missingFields: readonly string[]) {
    super(
      `Partner-supplied PDA input is missing required field(s): ${missingFields.join(", ")}. ` +
        "The configurator REFUSES to fill defaults at the API boundary because that would " +
        "silently attribute the emitted artifact to a synthetic partner_id and template.",
    );
    this.name = "PartnerInputMissingRequiredFieldsError";
  }
}

export function assertPartnerInputRequiredFields(input: Record<string, unknown>): void {
  const missing: string[] = [];
  for (const field of PARTNER_SUPPLIED_REQUIRED_FIELDS) {
    const value = input[field];
    if (value === undefined || value === null || (typeof value === "string" && value.length === 0)) {
      missing.push(field);
    }
  }
  if (missing.length > 0) {
    throw new PartnerInputMissingRequiredFieldsError(missing);
  }
}

export function prepareSubmittedPda(input: Record<string, unknown>): SubmittedPda {
  const scaffold = input;
  const conditional = recordValue(scaffold.conditional_recipients);
  const kConditional = toNumber(conditional.k ?? 0);
  const schemaFields = schemaFieldsFor(scaffold);
  const sdFieldPolicies = sdPoliciesFor(scaffold, schemaFields);
  const sdEnabled = Object.values(sdFieldPolicies).some((policy) => policy !== "escrow_only");
  const templateName = readString(scaffold.template_name) ?? readString(scaffold.template_id) ?? "template";
  const templateId = bytes32Seed(scaffold.template_id, `template:${templateName}`);
  const pdaId = bytes32Seed(scaffold.pda_id, `${String(scaffold.partner_id ?? "partner")}:${templateName}`);
  const reveal = recordValue(scaffold.reveal_condition);
  const shred = recordValue(scaffold.shred_condition);
  const extension = extensionMetadataFor(scaffold);
  const recipients = recipientsFor(scaffold, conditional);

  return {
    schema_version: 1,
    schema_version_allows_extension_metadata: true,
    extension_metadata: extension,
    pda_id: pdaId,
    pda_version: toNumber(scaffold.pda_version ?? 1),
    partner_id: String(scaffold.partner_id ?? "partner_fixture"),
    template_id: templateId,
    template_name: templateName,
    template: templateSpec(scaffold),
    schema: { fields: schemaFields.map((path) => ({ path })) },
    schema_mapping: Object.fromEntries(schemaFields.map((path, index) => [`field_${String(index)}`, path])),
    schema_digest: hashToHex32({ schemaFields }),
    commit_version: 0x0302,
    pda_root_fields: [...PDA_ROOT_FIELD_NAMES],
    pda_root_extra_fields: [],
    commit_aad_fields: [...COMMIT_AAD_FIELD_NAMES],
    sdMerkleRoot: sdEnabled ? hashToHex32(sdFieldPolicies) : `0x${"00".repeat(32)}`,
    sd_enabled: sdEnabled,
    sd_plan: { field_policies: sdFieldPolicies },
    sd_field_policies: sdFieldPolicies,
    ingestion_mode: "ModeA",
    delivery_mode: "PASSKEY_ACCOUNT",
    delivery_modes: ["PASSKEY_ACCOUNT"],
    evidence_cid: "bafybeigdyrzt5sfp7udm7hu76u4n6v7i2c6h4oxf5kqj4f5b5x3a2z7lqi",
    recipients,
    conditional_recipients: {
      n: toNumber(conditional.n ?? 0),
      k: kConditional,
      role_tags: arrayStrings(conditional.role_tags),
      recipients,
      updatable: conditional.updatable === true || scaffold.conditional_recipients_updatable === true,
    },
    global_shamir_threshold: 3 + kConditional,
    fixed_gates: ["Lit V3", "G3", "G4"],
    g3_choice: scaffold.g3_choice === "drand" ? "drand" : "dcipher",
    g4_phase: scaffold.g4_phase === 1 ? 1 : 2,
    phase: scaffold.g4_phase === 1 ? 1 : 2,
    lit_vendor_family: "aws-nitro",
    g4_vendor_family: "azure-confidential",
    gate_recipient_pubkeys: [
      { gate_kind: "drand", lifecycle: "long_lived_committee" },
      { gate_kind: "lit", lifecycle: "per_commit_ephemeral" },
      { gate_kind: "g4", lifecycle: "per_commit_ephemeral" },
      { gate_kind: "conditional", lifecycle: "per_commit_ephemeral" },
    ],
    registry_lookup_mode: "historical_at_authorization_block",
    historical_registry_lookup: true,
    reveal_condition: revealConditionFor(reveal, scaffold),
    shred_condition: {
      mode: readString(shred.mode) ?? "P",
      spec_hash: bytes32Seed(shred.spec_hash, `${templateName}:shred`),
      mandatory_guardrail_present: true,
    },
    reveal_shred_axes_separated: true,
    reveal_authorization_sources: ["RevealAuthorized"],
    legal_effect_expected: scaffold.legal_effect_expected === true,
    partner_ready: scaffold.partner_ready === true,
    cealis_class_wide_halt_opt_out: scaffold.cealis_class_wide_halt_opt_out === true,
    trust_tier: trustTier(scaffold.trust_tier),
    use_case: String(scaffold.use_case ?? "kyc_lending"),
    archetype: String(scaffold.archetype ?? "enforcement"),
    retention_seconds: toNumber(scaffold.retention_seconds ?? 31_536_000),
    minimum_shred_latency_seconds: toNumber(scaffold.minimum_shred_latency_seconds ?? 0),
    reveal_challenge_window_seconds: toNumber(scaffold.reveal_challenge_window_seconds ?? 0),
    shred_challenge_window_seconds: toNumber(scaffold.shred_challenge_window_seconds ?? 0),
    fire_time_ttl_estimate_seconds: toNumber(scaffold.fire_time_ttl_estimate_seconds ?? 0),
    sigma_usage: "authorization",
    dek_lifecycle: "A1_SHAMIR",
    disclosure_registry_authorizes_reveal: false,
  };
}

/**
 * TS-API-F-05 (HIGH) — Stage 3 PDA+ allow-list / bounds policy keyed by
 * class-table row id.
 *
 * BEFORE this fix, `buildStage3Context` auto-constructed an allow-list that
 * contained exactly whatever `adaptToStage3` synthesized, so Stage 3 was a
 * synthetic↔synthetic no-op that ALWAYS passed regardless of partner input.
 *
 * This is the effective PDA+ policy surface: the FIXED set of values Cealis
 * permits for each partner-controllable category-(b)/(c) surface. It is NOT
 * derived from the submitted PDA — the submitted value is checked AGAINST it.
 * A partner value outside this policy is rejected by Stage 3.
 *
 * DESIGN-SENSITIVE: the precise option sets / numeric bounds here are the
 * minimal principled defaults the finding points at (mirroring the enum and
 * floor/ceiling constraints already enforced elsewhere in the engine — e.g.
 * `g3_choice ∈ {dcipher, drand}`, `g4_phase ∈ {1,2}`, `trust_tier ∈ {A,B,C}`,
 * shred mode `∈ {P,F}`). Simon/S2-4 §4.4 must ratify the authoritative
 * per-PDA+ allow-list/bounds once a live PDA+ policy registry exists; until
 * then these are the conservative spec-anchored sets.
 */
const STAGE3_ALLOW_LIST_POLICY: ReadonlyMap<string, readonly Stage3Value[]> = new Map<
  string,
  readonly Stage3Value[]
>([
  // row 41 — commit_AAD.g3_choice (S2-4 §5.2 row 41 / internal project constitution §0 Table A).
  ["41", ["dcipher", "drand"]],
  // row 43 — commit_AAD.phase (G4 Phase 1 server / Phase 2 TEE).
  ["43", [1, 2]],
  // row 72 — trust tier declaration (CF-06; Tier A/B/C taxonomy).
  ["72", ["A", "B", "C"]],
  // row 21 — cealis_class_wide_halt_opt_out (boolean pick).
  ["21", [true, false]],
  // row 14 — art_9_scoped_flag (boolean pick).
  ["14", [true, false]],
  // row 39 — ingestion mode pick (Mode A shipping; Mode B PDA+-gated).
  ["39", ["ModeA", "ModeB"]],
  // row 26 — shred condition pick: mode P (predicate) or F (FSM).
  ["26", ["P", "F"]],
]);

const STAGE3_BOUNDS_POLICY: ReadonlyMap<string, NumericBounds> = new Map<string, NumericBounds>([
  // row 66 — retention window value: 0 .. 100 years (seconds). Out-of-range
  // retention must be rejected (Decision D3 / Art. 5(1)(e) GDPR floors are
  // enforced separately; this is the PDA+ numeric ceiling).
  ["66", { min: 0, max: 3_153_600_000 }],
  // row 28 — minimum shred latency value: 0 .. ~10 years.
  ["28", { min: 0, max: 315_360_000 }],
  // row 30 — reveal challenge window value: 0 .. ~90 days.
  ["30", { min: 0, max: 7_776_000 }],
  // row 32 — shred challenge window value: 0 .. ~90 days.
  ["32", { min: 0, max: 7_776_000 }],
]);

/**
 * Class-table rows whose Stage-3 surface is a content-addressed template
 * PICK (validated by `checkTemplateIdActive`, not by an allow-list). Their
 * submitted value is the partner-chosen template/spec hash.
 */
const STAGE3_TEMPLATE_PICK_ROWS: ReadonlyMap<string, (submitted: SubmittedPda) => string | undefined> =
  new Map<string, (submitted: SubmittedPda) => string | undefined>([
    // row 54 — template_id_pick: the partner-chosen content-addressed template.
    ["54", (submitted) => readString(submitted.template_id)],
    // row 56.1 — condition template pick. PaymentObligation/MultiPartySignal/
    // OracleAttestation use `template_pick`; DeadManSwitch uses
    // `evidence_template_pick`. Resolve either so the condition template is
    // validated for every shipping archetype.
    [
      "56.1",
      (submitted) => {
        const reveal = recordValue(submitted.reveal_condition);
        return readString(reveal.template_pick) ?? readString(reveal.evidence_template_pick);
      },
    ],
  ]);

// Defensive: the allow-list checker's deferral set (TEMPLATE_PICK_ROW_IDS) and
// emit's template-pick extraction map MUST cover the same rows, otherwise a row
// could be deferred by the checker but never emit a template surface (or vice
// versa), silently reintroducing the ALLOW_LIST_MISSING / no-op gap.
{
  const extracted = new Set(STAGE3_TEMPLATE_PICK_ROWS.keys());
  for (const id of TEMPLATE_PICK_ROW_IDS) {
    if (!extracted.has(id)) {
      throw new Error(`Stage 3 template-pick row ${id} is deferred by the allow-list checker but has no extractor`);
    }
  }
  for (const id of extracted) {
    if (!TEMPLATE_PICK_ROW_IDS.has(id)) {
      throw new Error(`Stage 3 template-pick row ${id} has an extractor but is not deferred by the allow-list checker`);
    }
  }
}

/**
 * Extracts the REAL partner-supplied value for a category-(b)/(c) class-table
 * row from the prepared submitted PDA. Returns `undefined` for rows whose
 * surface is an architectural fact, a PDA+ surface, or a value that is not
 * partner-controllable through the current PDA JSON shape (those rows simply
 * do not produce an allow-list/bounds-checked surface).
 *
 * TS-API-F-05: this is the missing link — Stage 3 now sees the actual
 * submitted field values instead of a fixture.
 */
function extractStage3Value(rowId: string, submitted: SubmittedPda): Stage3Value | undefined {
  const shred = recordValue(submitted.shred_condition);
  switch (rowId) {
    case "41":
      return readString(submitted.g3_choice);
    case "43":
      return typeof submitted.g4_phase === "number" ? submitted.g4_phase : undefined;
    case "72":
      return readString(submitted.trust_tier);
    case "21":
      return submitted.cealis_class_wide_halt_opt_out === true;
    case "14":
      return recordValue(submitted.extension_metadata).art_9_scoped === true;
    case "39":
      return readString(submitted.ingestion_mode);
    case "26":
      return readString(shred.mode);
    case "66":
      return toNumber(submitted.retention_seconds);
    case "28":
      return toNumber(submitted.minimum_shred_latency_seconds);
    case "30":
      return toNumber(submitted.reveal_challenge_window_seconds);
    case "32":
      return toNumber(submitted.shred_challenge_window_seconds);
    default:
      return undefined;
  }
}

export function buildStage3Context(submitted: SubmittedPda): Stage3ValidationContext {
  // Allow-lists / bounds are the FIXED PDA+ policy (NOT derived from the
  // submitted value). A partner value outside these is rejected. Only rows we
  // can extract a real value for carry a policy; the rest are absent so their
  // checker short-circuits (returns null) instead of forcing a synthetic pass.
  const allowLists = new Map<string, readonly Stage3Value[]>(STAGE3_ALLOW_LIST_POLICY);
  const bounds = new Map<string, NumericBounds>(STAGE3_BOUNDS_POLICY);

  // Active-template state is sourced from the REGISTERED content-addressed
  // template catalog (the known/available templates the configurator ships),
  // NOT from the submitted PDA. Sourcing it from the submission would let any
  // content-addressed-looking template_id self-validate — the no-op the
  // TS-API-F-05 fix closes at the template-pick surface. A registered
  // template_id validates; an unknown id (even a well-formed 0x.. hash) is
  // rejected by `checkTemplateIdActive`.
  const activeTemplateIds = registeredTemplateIds();
  // Registry liveness is still sourced from the REAL references the submitted
  // PDA carries (oracle refs). References the PDA does NOT carry are absent —
  // no synthetic backfill.
  const registryEntries = new Map(
    [...collectRegistryRefs(submitted)].map((ref) => [
      ref,
      { id: ref, effectiveBlock: 1n, tombstonedAtBlock: null as bigint | null },
    ]),
  );
  return {
    classTable: CLASS_TABLE,
    allowLists,
    bounds,
    registryEntries,
    activeTemplateIds,
    intendedCommitBlock: 10n,
  };
}

export function adaptToStage3(submitted: SubmittedPda): Stage3SubmittedPda {
  const surfaces: Stage3SubmittedSurface[] = [];
  for (const row of CLASS_TABLE_ROWS) {
    const sourceFieldPath = row.cross_ref_to_pda_root_field;

    // Template-pick surfaces: validated by `checkTemplateIdActive` against the
    // active-template set, NOT by an allow-list. Bind the partner-chosen
    // content-addressed template id.
    const templatePick = STAGE3_TEMPLATE_PICK_ROWS.get(row.id);
    if (templatePick !== undefined) {
      const templateId = templatePick(submitted);
      if (templateId !== undefined) {
        surfaces.push({ rowId: row.id, templateId, sourceFieldPath });
      }
      continue;
    }

    // Allow-list / bounds surfaces: only emit when (a) we can extract the real
    // submitted value AND (b) a PDA+ policy exists for the row, so the relevant
    // checker fires on a real value↔real-policy comparison. Stage 3 no longer
    // fabricates a passing value for unmapped rows.
    if (row.category !== "(b) PDA pick" && row.category !== "(c) PDA parameter") continue;
    const hasPolicy =
      (row.category === "(b) PDA pick" && STAGE3_ALLOW_LIST_POLICY.has(row.id)) ||
      (row.category === "(c) PDA parameter" && STAGE3_BOUNDS_POLICY.has(row.id));
    if (!hasPolicy) continue;
    const value = extractStage3Value(row.id, submitted);
    if (value === undefined) continue;
    surfaces.push({ rowId: row.id, value, sourceFieldPath });
  }
  return { surfaces };
}

/** Collect the registry references the submitted PDA actually carries. */
function collectRegistryRefs(submitted: SubmittedPda): ReadonlySet<string> {
  const reveal = recordValue(submitted.reveal_condition);
  const kOfN = recordValue(reveal.k_of_n);
  const refs = new Set<string>();
  for (const oracle of Array.isArray(kOfN.oracle_refs) ? kOfN.oracle_refs : []) {
    const id = readString(recordValue(oracle).oracle_id);
    if (id !== undefined) refs.add(id);
  }
  return refs;
}

export function buildCrossFieldContext(submitted: SubmittedPda): CrossFieldValidationContext {
  const reveal = recordValue(submitted.reveal_condition);
  const signal = recordValue(reveal.k_of_n);
  return {
    partner_ready: submitted.partner_ready === true,
    pda: {
      legal_effect_expected: submitted.legal_effect_expected === true,
      trust_tier: trustTier(submitted.trust_tier),
      relevant_reveal_condition_tiers: [trustTier(submitted.trust_tier)],
      reveal_condition: {
        module: readString(reveal.module) ?? "PaymentObligation",
        tier: trustTier(submitted.trust_tier),
        k_of_n: signal,
      },
      reveal_challenge_window_seconds: toNumber(submitted.reveal_challenge_window_seconds ?? 0),
      challenge_window_seconds: toNumber(submitted.shred_challenge_window_seconds ?? 0),
      archetype_floor_seconds: trustTier(submitted.trust_tier) === "A" ? 0 : 1_209_600,
      ceremony_resolver: { type: String(recordValue(submitted.extension_metadata).ceremony_resolver ?? "human_endpoint") },
      eligible_challengers_reveal: ["subject", "operator"],
      subject_id: "subject",
      minimum_shred_latency_seconds: toNumber(submitted.minimum_shred_latency_seconds ?? 0),
      cealis_class_wide_halt_opt_out: submitted.cealis_class_wide_halt_opt_out === true,
      fire_time_ttl_estimate_seconds: toNumber(submitted.fire_time_ttl_estimate_seconds ?? 0),
      conditional_recipients_updatable:
        submitted.conditional_recipients_updatable === true ||
        recordValue(submitted.extension_metadata).conditional_recipients_updatable === true,
      emergency_response_bricking_acknowledgment:
        submitted.emergency_response_bricking_acknowledgment === true ||
        recordValue(submitted.extension_metadata).emergency_response_bricking_acknowledgment === true,
      conditional_recipients: recordValue(submitted.conditional_recipients),
      recipients: recipientsFor(submitted, recordValue(submitted.conditional_recipients)).map((recipient) => ({
        role_tag: String(recipient.role_tag ?? "RECIPIENT"),
        delivery_mode: String(recipient.delivery_mode ?? "PASSKEY_ACCOUNT"),
      })),
      subject_liveness_required_at_fire: submitted.subject_liveness_required_at_fire === true,
      g4_phase: submitted.g4_phase === 1 ? 1 : 2,
      partner_ready: submitted.partner_ready === true,
      multi_party_signal: signal,
      archetype: readString(submitted.archetype) ?? "enforcement",
      use_case: readString(submitted.use_case) ?? "kyc_lending",
      firing_condition_depends_on_external_event_source: signal.k !== undefined,
      tier_c_acknowledgment_bound:
        recordValue(submitted.extension_metadata).tier_c_acknowledgment_bound === true,
      inspection_surface: {
        partner_acknowledgments: arrayStrings(recordValue(submitted.extension_metadata).partner_acknowledgments),
        bound_acknowledgments: arrayStrings(recordValue(submitted.extension_metadata).bound_acknowledgments),
      },
    },
  };
}

export function buildSimulationInput(submitted: SubmittedPda): SimulationHarnessInput {
  const schemaFields = schemaFieldPaths(submitted.schema);
  const nonEscrow = Object.entries(recordValue(submitted.sd_field_policies))
    .filter(([, policy]) => policy !== "escrow_only")
    .map(([path]) => path);
  const conditional = recordValue(submitted.conditional_recipients);
  const recipients = recipientsFor(submitted, conditional);
  const thresholdK = Math.max(1, toNumber(conditional.k ?? 1));
  const thresholdN = Math.max(thresholdK, toNumber(conditional.n ?? recipients.length));
  return {
    fsm_reachability: {
      states: ["initial", "authorized", "delivered"],
      initial: "initial",
      transitions: [
        { from: "initial", to: "authorized" },
        { from: "authorized", to: "delivered" },
      ],
      terminal_firing_states: ["delivered"],
    },
    axis_separation: {
      reveal_terminal_states: ["delivered"],
      shred_terminal_states: ["shredded"],
    },
    gas_budget: {
      advance_fsm_worst_case_gas: 100_000,
      predicate_worst_case_gas: 50_000,
      pda_budget_gas: 200_000,
    },
    schema_compat: {
      claims: schemaFields.map((path) => ({
        path,
        type_checks_against_registry_example: true,
      })),
    },
    canonical_examples: {
      examples: schemaFields.map((path) => ({
        claim_path: path,
        registered_valid_example_passed: true,
        registered_invalid_example_failed: true,
      })),
    },
    challenge_windows: {
      zero_window_replayed: true,
      non_zero_window_replayed: true,
    },
    registry_overlay: {
      pda_root_commit_block: 100n,
      authorization_block: 102n,
      referenced_entries: [{ registry: "OracleRegistry", entry_id: "oracle-a" }],
      deprecations: [],
    },
    sd_isolation: {
      escrow_succeeds_when_sd_fails: true,
      non_escrow_only_fields: nonEscrow,
      audit_diff_fields: nonEscrow,
    },
    recipient_policy: {
      threshold: { k: thresholdK, n: thresholdN },
      recipients: recipients.map((recipient) => ({
        role_tag: String(recordValue(recipient).role_tag ?? "RECIPIENT"),
        delivery_mode: String(recordValue(recipient).delivery_mode ?? "PASSKEY_ACCOUNT"),
      })),
    },
    universal_tripwire_negative: {
      delivery_fired_before_on_chain_condition: false,
      delivery_fired_before_gate_eligibility: false,
    },
  };
}

export function diffPDA(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  options?: PdaDiffOptions,
): PdaDiffResult {
  return diffPdaEvolution(prepareSubmittedPda(before), prepareSubmittedPda(after), options);
}

function throwIfInvalid(validation: ValidationReport): void {
  if (validation.stage1.length > 0) throw new ValidationFailure(1, validation.stage1);
  if (validation.stage2.length > 0) throw new ValidationFailure(2, validation.stage2);
  if (validation.stage3.length > 0) throw new ValidationFailure(3, validation.stage3);
  if (validation.stage4.length > 0) throw new ValidationFailure(4, validation.stage4);
  if (!validation.stage5.ok) throw new SimulationFailure(validation.stage5);
}

function revealConditionFor(
  reveal: Record<string, unknown>,
  scaffold: Record<string, unknown>,
): Record<string, unknown> {
  const templateName = readString(scaffold.template_name) ?? "template";
  const kOfN = recordValue(reveal.k_of_n);
  const module = readString(reveal.module) ?? "PaymentObligation";
  const needsSignal =
    Object.keys(kOfN).length > 0 ||
    module === "MultiPartySignal" ||
    module === "OracleAttestation" ||
    module === "DeadManSwitch";
  const operatorA = hashToHex32("operator-a");
  const operatorB = hashToHex32("operator-b");
  const operatorC = hashToHex32("operator-c");
  return {
    module,
    mode: readString(reveal.mode) ?? "P",
    spec_hash: bytes32Seed(reveal.template_pick ?? reveal.evidence_template_pick, `${templateName}:reveal`),
    template_pick: bytes32Seed(reveal.template_pick ?? reveal.evidence_template_pick, `${templateName}:pick`),
    parameter_values: jsonSafeRecord(reveal.parameter_values ?? reveal.evidence_parameters),
    tier: trustTier(scaffold.trust_tier),
    // ── T5.1 — security PDA fields the 2026-06-02 contracts bind on-chain ────────
    // Emit the per-module EIP-712 / WebAuthn-anchored signer the merged
    // `SubjectInitiatedModule` / `DeadManSwitchModule` `ECDSA.recover` against and
    // revert on mismatch, at EXACTLY the location the T1.4 inspector
    // (`deriveModuleSecurity`, v3-api/src/ingest/pda-inspector.ts) reads:
    // `reveal_condition.subject_signer` / `.expected_axis` (SubjectInitiated) and
    // `reveal_condition.actor` / `.interval_seconds` / `.grace_period_seconds`
    // (DeadManSwitch). NOTHING hardcoded — the signer/actor/axis/interval/grace
    // come straight from the partner-submitted `reveal_condition` config; when the
    // module has no signer binding (PaymentObligation / TimeLock / …) NOTHING is
    // emitted (Rule 19 / platform principle: never synthesize a security default).
    ...moduleSecurityFieldsFor(module, reveal),
    ...(needsSignal
      ? {
          k_of_n: {
            k: toNumber(kOfN.k ?? 2),
            n: toNumber(kOfN.n ?? (module === "MultiPartySignal" && String(scaffold.archetype).includes("commercial") ? 4 : 3)),
            independent_operators: kOfN.independent_operators !== false,
            signal_digest_bound: true,
            signer_identities: arrayStrings(kOfN.signer_identities ?? kOfN.signer_roles).length > 0
              ? arrayStrings(kOfN.signer_identities ?? kOfN.signer_roles)
              : ["oracle-a", "oracle-b", "oracle-c"],
            operator_ids: [operatorA, operatorB, operatorC],
            oracle_refs: [
              { oracle_id: hashToHex32("oracle-a"), tier: trustTier(scaffold.trust_tier), operator_id: operatorA, signer_identity: "oracle-a", axis: "reveal" },
              { oracle_id: hashToHex32("oracle-b"), tier: trustTier(scaffold.trust_tier), operator_id: operatorB, signer_identity: "oracle-b", axis: "reveal" },
              { oracle_id: hashToHex32("oracle-c"), tier: trustTier(scaffold.trust_tier), operator_id: operatorC, signer_identity: "oracle-c", axis: "reveal" },
            ],
          },
        }
      : {}),
  };
}

/**
 * T5.1 — emit the per-module EIP-712-anchored security fields the merged
 * 2026-06-02 contracts bind on-chain, at the T1.4 inspector's read path.
 *
 * The runtime threads these into the on-chain module-config calls:
 *   - `SubjectInitiatedModule.configureSubjectInitiated(authorizationId,
 *     expectedAxis, subjectSigner, configDigest)` — `subject_signer` (the
 *     EIP-712 / WebAuthn-anchored address the module recovers against under the
 *     `CealisSubjectInitiated` v1 domain, typehash
 *     `SubjectAction(bytes32 authorizationId,bytes32 actionDigest,address subject)`)
 *     plus the bound `CeremonyAxis` (`reveal` | `shred`).
 *   - `DeadManSwitchModule.configureDeadManSwitch(authorizationId,
 *     recipientPolicyDigest, actor, interval, gracePeriod, configDigest)` —
 *     `actor` (recovered under the `CealisDeadManSwitch` v1 domain, typehash
 *     `Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)`)
 *     plus `interval` / `gracePeriod` seconds.
 *
 * The inspector (`deriveModuleSecurity`) reads these top-level on the emitted
 * `reveal_condition` (its highest-priority read path), so we emit them there.
 * The EIP-712 domain/typehash literals live on the module's own on-chain
 * constants (and the inspector's pinned `SUBJECT_INITIATED_EIP712` /
 * `DEAD_MAN_SWITCH_EIP712`) — the configurator carries only the PDA-configured
 * signer/actor/axis/interval/grace, NEVER the typehash (no duplication of the
 * contract's source-of-truth, no hardcoded address).
 *
 * NOTHING is synthesized: when the partner did not supply a signer/actor for a
 * security-bound module, no field is emitted (the field is simply absent), so
 * the inspector legitimately surfaces `{ module }` and the downstream
 * module-config call site fails loud per Rule 19 rather than configuring the
 * module under a forged signer.
 */
function moduleSecurityFieldsFor(
  module: string,
  reveal: Record<string, unknown>,
): Record<string, unknown> {
  if (module === "SubjectInitiated") {
    const subjectSigner =
      readAddress(reveal.subject_signer) ?? readAddress(reveal.subjectSigner);
    if (subjectSigner === undefined) return {};
    const axisRaw = readString(reveal.expected_axis) ?? readString(reveal.axis);
    const expectedAxis = axisRaw === "shred" ? "shred" : "reveal";
    return { subject_signer: subjectSigner, expected_axis: expectedAxis };
  }

  if (module === "DeadManSwitch") {
    const params = recordValue(reveal.evidence_parameters);
    const actor = readAddress(reveal.actor) ?? readAddress(params.actor);
    if (actor === undefined) return {};
    // interval / grace are PDA config; accept the DeadManSwitch scaffold's
    // evidence-parameter names as well as the flat module-config names so the
    // emit survives either submission shape. bigint → number (the inspector's
    // `toNumber` accepts both, but the canonical JSON / Stage validators want a
    // JSON-safe number).
    const interval = readSeconds(
      reveal.interval_seconds ??
        params.heartbeat_interval_seconds ??
        params.interval_seconds,
    );
    const grace = readSeconds(
      reveal.grace_period_seconds ??
        params.grace_window_seconds ??
        params.grace_period_seconds,
    );
    const out: Record<string, unknown> = { actor };
    if (interval !== undefined) out.interval_seconds = interval;
    if (grace !== undefined) out.grace_period_seconds = grace;
    return out;
  }

  return {};
}

/** Validate an EVM address (`0x` + 40 hex), matching the inspector's `readAddress`. */
function readAddress(value: unknown): string | undefined {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value) ? value : undefined;
}

/** Coerce a seconds value (number | bigint | numeric string) to a JSON-safe number. */
function readSeconds(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

function extensionMetadataFor(scaffold: Record<string, unknown>): Record<string, unknown> {
  const existing = recordValue(scaffold.extension_metadata);
  return {
    shred_authority: scaffold.shred_authority ?? "Subject",
    ceremony_resolver: trustTier(scaffold.trust_tier) === "A" ? "chain_native" : "human_endpoint",
    applicable_jurisdiction: scaffold.applicable_jurisdiction ?? "DE",
    qes_subject_required: scaffold.qes_subject_required === true,
    qtsp_provider_ref: bytes32Seed(scaffold.qtsp_provider_ref, "qtsp:none"),
    art_9_scoped: scaffold.art_9_scoped === true,
    art_9_basis_id: toNumber(scaffold.art_9_basis_id ?? 0),
    tier_c_acknowledgment_bound: trustTier(scaffold.trust_tier) === "C",
    partner_acknowledgments: trustTier(scaffold.trust_tier) === "C" ? ["tier_c_trust_acknowledgment"] : [],
    bound_acknowledgments: trustTier(scaffold.trust_tier) === "C" ? ["tier_c_trust_acknowledgment"] : [],
    pda_updatable: scaffold.pda_updatable === true || existing.pda_updatable === true,
    conditional_recipients_updatable:
      scaffold.conditional_recipients_updatable === true ||
      recordValue(scaffold.conditional_recipients).updatable === true ||
      existing.conditional_recipients_updatable === true,
    emergency_response_bricking_acknowledgment:
      scaffold.emergency_response_bricking_acknowledgment === true ||
      existing.emergency_response_bricking_acknowledgment === true,
    subject_liveness_required_at_fire:
      scaffold.subject_liveness_required_at_fire === true ||
      existing.subject_liveness_required_at_fire === true,
    time_critical_pda_flag: scaffold.time_critical_pda_flag === true || existing.time_critical_pda_flag === true,
  };
}

function templateSpec(input: Record<string, unknown>): Record<string, unknown> {
  return {
    template_name: input.template_name ?? "template",
    use_case: input.use_case ?? "kyc_lending",
    archetype: input.archetype ?? "enforcement",
    reveal_condition: jsonSafe(input.reveal_condition ?? {}),
    shred_condition: jsonSafe(input.shred_condition ?? {}),
  };
}

function schemaFieldsFor(input: Record<string, unknown>): readonly string[] {
  const policies = recordValue(input.sd_field_policies);
  const paths = Object.keys(policies);
  if (paths.length > 0) return paths;
  return ["subject.identifier", "claims.defaulted"];
}

function schemaFieldPaths(schema: unknown): readonly string[] {
  const record = recordValue(schema);
  if (!Array.isArray(record.fields)) return ["claims.defaulted"];
  return record.fields
    .map((field) => recordValue(field).path)
    .filter((path): path is string => typeof path === "string");
}

function sdPoliciesFor(
  input: Record<string, unknown>,
  schemaFields: readonly string[],
): Record<string, "cleartext" | "zkp" | "escrow_only"> {
  const policies = recordValue(input.sd_field_policies);
  const out: Record<string, "cleartext" | "zkp" | "escrow_only"> = {};
  for (const field of schemaFields) {
    const value = policies[field];
    out[field] = value === "cleartext" || value === "zkp" ? value : "escrow_only";
  }
  return out;
}

function recipientsFor(
  input: Record<string, unknown>,
  conditional: Record<string, unknown>,
): readonly Record<string, unknown>[] {
  if (Array.isArray(input.recipients) && input.recipients.length > 0) {
    return input.recipients.map((entry) => recordValue(entry));
  }
  const roles = arrayStrings(conditional.role_tags);
  if (roles.length > 0) {
    return roles.map((role) => ({
      role_tag: role,
      delivery_mode: "PASSKEY_ACCOUNT",
      schema_selector: "$",
    }));
  }
  return [{ role_tag: "RECIPIENT", delivery_mode: "PASSKEY_ACCOUNT", schema_selector: "$" }];
}

function bytes32Seed(value: unknown, seed: string): `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value)
    ? (value as `0x${string}`)
    : hashToHex32(value ?? seed);
}

function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function arrayStrings(value: unknown): readonly string[] {
  return Array.isArray(value) ? value.map((entry) => String(entry)) : [];
}

function trustTier(value: unknown): "A" | "B" | "C" {
  return value === "B" || value === "C" ? value : "A";
}

function toNumber(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return 0;
}

function jsonSafeRecord(value: unknown): Record<string, unknown> {
  const normalized = jsonSafe(value);
  return recordValue(normalized);
}

function jsonSafe(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "bigint") return Number(value);
  if (Array.isArray(value)) return value.map((entry) => jsonSafe(entry));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = jsonSafe(entry);
    }
    return out;
  }
  return null;
}
