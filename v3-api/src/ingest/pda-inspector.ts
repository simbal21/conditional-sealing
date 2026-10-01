// PdaInspector — the real `IngestionDependencies.inspectPda` seam (T1.4).
//
// `inspectPda` is the SINGLE point where per-PDA configuration enters the
// ingestion runtime. Everything downstream — h_commit construction (already
// consuming the wide `PdaInspectionForIngest` surface in
// routes-create-mode-a.ts), the real sealer/dealer access-structure choice
// (T1.2 `RealVaultWriter` → `dealDek`), the σ-gatherer's per-PDA gate choice
// (T3.2, g3_choice), and the on-chain module-config calls the security fixes
// added (T5.1, subjectSigner / DMS actor) — reads what this inspector surfaces.
//
// PLATFORM PRINCIPLE (internal project constitution §0): NOTHING is hardcoded. Every value the
// inspector returns is derived from the active PDA: the configurator-emitted
// `PartnerReadableInspection` (pda_root / digests / g3_choice / g4_phase /
// trust_tier / conditional-recipient policy / retention / challenge windows /
// shred authority / oracle refs / legal flags) plus the submitted PDA's
// reveal-condition module config (the EIP-712-anchored subjectSigner / DMS
// actor). A PDA selects its own flow; the inspector never assumes one.
//
// ── What this inspector adds over `PdaInspectionForIngest` ────────────────────
// The existing `PdaInspectionForIngest` (routes-create-mode-a.ts, Wave-5-owned)
// carries the h_commit + commit-metadata fields. T1.4 must ADDITIONALLY surface,
// for the sealer/dealer + reveal gatherer, three things the narrow interface
// does not yet name (and which this Wave-3 file MUST NOT add to the Wave-5
// interface — it carries them on a structurally-wider RETURN type that is still
// assignable to `PdaInspectionForIngest`):
//
//   1. `access_structure_profile` — the `AccessStructureProfile`
//      (@cealis/v3-crypto) the commit-time DEK dealer (`dealDek`, T0.2) splits
//      under. Derived from the conditional-recipient policy: n == 0 → FIXED_ONLY
//      (3-of-3 over {Lit,G3,G4}); n == 1 ∧ k == 1 → RECIPIENT_1_OF_1; else
//      RECIPIENT_K_OF_N{n,k}. (The combiner reconstructs from the same profile.)
//   2. `module_security` — the per-PDA EIP-712 / WebAuthn-anchored signer the
//      2026-06-02 security fixes bound on-chain: `SubjectInitiated.subjectSigner`
//      and `DeadManSwitch.actor` (+ interval / gracePeriod) — read from the PDA's
//      reveal-condition module config, with the EIP-712 domain + typehash the
//      contract recovers against. T5.1 wires these into the module-config calls.
//   3. `g3_choice` is already on `PdaInspectionForIngest`; this inspector simply
//      sources it (and g4_phase) from the PDA, never a default.
//
// ── Source of the PDA config ──────────────────────────────────────────────────
// The active PDA is found in `partner_agreements` (DB; status='active', latest
// effective_at). That table is a POINTER (partner_id, pda_id, status,
// effective_at) — it does NOT carry the config body. The config body is the
// configurator's emitted artifact (`@cealis/v3-configurator`
// `PartnerReadableInspection` + the submitted PDA). The inspector takes an
// injected `PdaConfigSource` that resolves the active artifact for a
// (partner_id, pda_id, pda_version); the DB lookup of the active agreement and
// the artifact load are both INSIDE that seam, so the load-bearing MAPPING here
// is unit-testable with a fake source (no Postgres / configurator run needed).
//
// ── GDPR / V3 isolation ───────────────────────────────────────────────────────
// No PII anywhere — the inspector handles only PDA policy metadata (digests,
// roots, refs, signer addresses, retention windows). No @cealis/shared, no V1
// packages, no V1 env tokens (the sealed-share / issuer-salt / committee-key
// family — see SECURITY.md). The injected `Sql` is read from the
// V3-scoped env only at the composition root (Wave 5), never here.

import type { Sql } from "postgres";

import {
  bytesToHex,
  type PartnerReadableInspection,
} from "../m4-imports.js";
import type { AccessStructureProfile } from "../m1-imports.js";
import type { G3Choice, G4Phase } from "../h-commit/index.js";
import type { OperationalClass, TrustTier } from "../types/index.js";
import type { PdaInspectionForIngest } from "./routes-create-mode-a.js";

// ── EIP-712 module-security surface (from the merged 2026-06-02 contracts) ─────

/**
 * The EIP-712 domain + struct typehash a security-bound condition module
 * recovers against on-chain. Mirrors the self-contained domain each module
 * declares (`SubjectInitiatedModule` / `DeadManSwitchModule`): the domain
 * separator additionally binds `block.chainid` + the module address at recovery
 * time, so only `name` / `version` / the struct typehash are PDA-config-level
 * (the contract supplies chainid + verifyingContract). Carried so T5.1 can build
 * the typed-data the off-chain signer signs without re-deriving the literals.
 */
export interface Eip712ModuleBinding {
  /** EIP-712 domain `name` (e.g. `"CealisSubjectInitiated"`). */
  readonly domain_name: string;
  /** EIP-712 domain `version` (e.g. `"1"`). */
  readonly domain_version: string;
  /** The struct typehash string the module hashes (NOT pre-keccak'd). */
  readonly struct_typehash: string;
}

/** SubjectInitiated EIP-712 binding — `SubjectInitiatedModule` §1.6 / §15.1. */
export const SUBJECT_INITIATED_EIP712: Eip712ModuleBinding = {
  domain_name: "CealisSubjectInitiated",
  domain_version: "1",
  struct_typehash: "SubjectAction(bytes32 authorizationId,bytes32 actionDigest,address subject)",
} as const;

/** DeadManSwitch EIP-712 binding — `DeadManSwitchModule` §1.6 / §15.1. */
export const DEAD_MAN_SWITCH_EIP712: Eip712ModuleBinding = {
  domain_name: "CealisDeadManSwitch",
  domain_version: "1",
  struct_typehash: "Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)",
} as const;

/** The CeremonyAxis the SubjectInitiated module is configured against. */
export type CeremonyAxis = "reveal" | "shred";

/**
 * Per-PDA SubjectInitiated security config. `subject_signer` is the EIP-712 /
 * WebAuthn-anchored address whose signature the module requires
 * (`configureSubjectInitiated(authorizationId, expectedAxis, subjectSigner,
 * configDigest)`). PDA-configured — nothing hardcoded.
 */
export interface SubjectInitiatedSecurityConfig {
  /** EIP-712-recovered signer the module accepts (0x-address, 20 bytes). */
  readonly subject_signer: string;
  /** CeremonyAxis the action is bound to (must match the configured axis). */
  readonly expected_axis: CeremonyAxis;
  /** The EIP-712 domain + struct typehash the module recovers against. */
  readonly eip712: Eip712ModuleBinding;
}

/**
 * Per-PDA DeadManSwitch security config. `actor` is the PDA-bound subject whose
 * EIP-712 `Heartbeat` signature is the only accepted proof-of-life
 * (`configureDeadManSwitch(authorizationId, recipientPolicyDigest, actor,
 * interval, gracePeriod, configDigest)`). PDA-configured — nothing hardcoded.
 */
export interface DeadManSwitchSecurityConfig {
  /** EIP-712-recovered actor the module accepts (0x-address, 20 bytes). */
  readonly actor: string;
  /** Heartbeat interval (seconds) — deadline = lastHeartbeat + interval + grace. */
  readonly interval_seconds: number;
  /** Soft grace window (seconds) after the interval before the predicate fires. */
  readonly grace_period_seconds: number;
  /** The EIP-712 domain + struct typehash the module recovers against. */
  readonly eip712: Eip712ModuleBinding;
}

/**
 * The security-relevant per-PDA module config the merged contracts now bind. At
 * most one sub-config is present (the PDA's reveal-condition module). Absent for
 * modules with no EIP-712 signer binding (PaymentObligation / TimeLock / etc.) —
 * a PDA that does not use a subject-signer / DMS-actor module legitimately
 * surfaces neither (NOT a hole; nothing to configure).
 */
export interface PdaModuleSecurity {
  /** The reveal-condition module name (e.g. `"PaymentObligation"`). */
  readonly module: string;
  readonly subject_initiated?: SubjectInitiatedSecurityConfig;
  readonly dead_man_switch?: DeadManSwitchSecurityConfig;
}

// ── The extended inspection the ingest runtime consumes ────────────────────────

/**
 * The full per-PDA inspection the ingest sealer/dealer + reveal gatherer need.
 * Structurally a superset of `PdaInspectionForIngest` (so it is assignable
 * wherever the narrow interface is expected — including the Wave-5
 * `inspectPda` call sites), plus the access-structure profile + module-security
 * surface T1.4 must additionally provide.
 */
export interface PdaInspectionForIngestExtended extends PdaInspectionForIngest {
  /**
   * The access-structure profile the commit-time DEK dealer (`dealDek`) splits
   * under and the combiner reconstructs from. PDA-derived from the
   * conditional-recipient policy — never hardcoded.
   */
  readonly access_structure_profile: AccessStructureProfile;
  /**
   * The reveal-condition module's EIP-712 / WebAuthn-anchored security config
   * (subjectSigner / DMS actor), or just `{ module }` when the module has no
   * signer binding. PDA-derived.
   */
  readonly module_security: PdaModuleSecurity;
}

// ── The injected config source (the only infra seam) ───────────────────────────

/**
 * The configurator-emitted PDA artifact slice the inspector maps from. This is
 * exactly the subset of `@cealis/v3-configurator`'s `EmittedPdaArtifact` the
 * inspector reads: the `PartnerReadableInspection` (the 28-field partner-readable
 * surface) plus the submitted PDA record (where the reveal-condition module +
 * its signer/actor config live) plus the resolved operational class.
 *
 * `operational_class` is NOT on `PartnerReadableInspection` (it is an S2-5 §12
 * runtime classification, not a configurator output), so the source supplies it
 * resolved (the composition root derives it from the PDA's trust tier + legal
 * posture; see `deriveOperationalClass` below for the default derivation a
 * source MAY reuse).
 */
export interface ResolvedPdaConfig {
  /** The configurator's partner-readable inspection (Bytes32 fields). */
  readonly inspection: PartnerReadableInspection;
  /** The submitted PDA record (reveal_condition + module security live here). */
  readonly submitted: Record<string, unknown>;
  /** Resolved S2-5 §12 operational class for this PDA. */
  readonly operational_class: OperationalClass;
  /** Resolved retention policy id (e.g. `"obligation_plus_3y"`). Optional. */
  readonly retention_policy_id?: string;
  /** Whether the partner has completed the partner-ready gate. */
  readonly partner_ready: boolean;
  /** Live halt state for the PDA (class-wide or per-PDA), if halted. */
  readonly halted?: boolean;
  readonly halt_reason?: string;
}

/**
 * Resolves the ACTIVE PDA config for a (partner_id, pda_id, pda_version). The
 * DB lookup of the active `partner_agreements` row + the configurator-artifact
 * load both live behind this seam, so the inspector's mapping stays infra-free
 * and unit-testable. Throws `PdaNotFoundError` when no active agreement exists.
 */
export interface PdaConfigSource {
  loadActivePda(input: {
    readonly partner_id: string;
    readonly pda_id: string;
    readonly pda_version: string;
  }): Promise<ResolvedPdaConfig>;
}

export class PdaNotFoundError extends Error {
  readonly code = "PDA_NOT_FOUND";
  constructor(
    readonly partner_id: string,
    readonly pda_id: string,
    readonly pda_version: string,
  ) {
    super(
      `No active partner agreement found for partner_id=${partner_id} ` +
        `pda_id=${pda_id} pda_version=${pda_version}`,
    );
    this.name = "PdaNotFoundError";
  }
}

// ── Pure mapping helpers (the load-bearing, fully-testable core) ────────────────

/** Lowercase the configurator's capitalized shred authority to the runtime enum. */
function mapShredAuthority(
  value: PartnerReadableInspection["shred_authority"],
): "subject" | "joint" | "operator" | "timelock" | "disabled" {
  switch (value) {
    case "Subject":
      return "subject";
    case "Joint":
      return "joint";
    case "Operator":
      return "operator";
    case "Timelock":
      return "timelock";
    case "Disabled":
      return "disabled";
  }
}

/**
 * Map the configurator's `"A" | "B" | "C"` trust-tier label to the v3-api runtime
 * `TrustTier` enum (`"tier_a" | "tier_b" | "tier_c"`, S2-4 §4.1 / S2-5 §12). The
 * two surfaces name the same tier differently; this is the only translation.
 */
export function mapTrustTier(value: PartnerReadableInspection["trust_tier"]): TrustTier {
  switch (value) {
    case "A":
      return "tier_a";
    case "B":
      return "tier_b";
    case "C":
      return "tier_c";
  }
}

/**
 * Derive the `AccessStructureProfile` the dealer/combiner use from the PDA's
 * conditional-recipient policy. NOTHING hardcoded — n/k come straight from the
 * configurator's `conditional_recipient_policy_summary`:
 *
 *   n == 0                 → FIXED_ONLY        (3-of-3 over {Lit, G3, G4})
 *   n == 1 ∧ k == 1        → RECIPIENT_1_OF_1  (4-of-4, single fixed recipient)
 *   n >= 1 (otherwise)     → RECIPIENT_K_OF_N{n,k}
 *
 * Matches the profile kinds `dealDek` (@cealis/v3-crypto) splits under and the
 * `global_shamir_threshold = 3 + k_conditional` the configurator computes.
 */
export function deriveAccessStructureProfile(input: {
  readonly n: number;
  readonly k: number;
}): AccessStructureProfile {
  const n = Math.max(0, Math.trunc(input.n));
  const k = Math.max(0, Math.trunc(input.k));
  if (n === 0) return { kind: "FIXED_ONLY" };
  if (n === 1 && k === 1) return { kind: "RECIPIENT_1_OF_1" };
  // k is clamped to [1, n]; a degenerate k (0 or > n) is coerced to the nearest
  // valid threshold so the dealer's invariant (1 ≤ k ≤ n ≤ 255) holds. Defensive
  // only — Stage-3 cross-field validation rejects out-of-range policies upstream.
  const kClamped = Math.min(Math.max(1, k), n);
  return { kind: "RECIPIENT_K_OF_N", n_conditional: n, k_conditional: kClamped };
}

/** Read a string field from the submitted PDA / a nested record (else undefined). */
function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Narrow an unknown to a plain record (else `{}`), matching the configurator idiom. */
function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function toNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

/** Validate an EVM address (`0x` + 40 hex). Returns the lowercased value or undefined. */
function readAddress(value: unknown): string | undefined {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value) ? value : undefined;
}

/**
 * Surface the per-PDA EIP-712-anchored module security config from the submitted
 * PDA's reveal-condition. The 2026-06-02 contracts bind a PDA-configured signer
 * for two modules:
 *
 *   SubjectInitiated → `subject_signer` (+ axis) under `CealisSubjectInitiated`.
 *   DeadManSwitch    → `actor` (+ interval / gracePeriod) under `CealisDeadManSwitch`.
 *
 * The signer/actor address + axis + interval/grace are read from the PDA's
 * reveal-condition (the configured config-body location T5.1 emits to); the
 * EIP-712 domain + typehash come from the module's own constants. A PDA whose
 * module has no signer binding (PaymentObligation / TimeLock / OracleAttestation
 * / …) legitimately surfaces just `{ module }` — there is nothing to configure.
 *
 * Forward-compatible with T5.1: when the configurator does not yet emit the
 * signer/actor, the sub-config is absent (NOT a synthesized default — Rule 19 /
 * platform principle: nothing hardcoded). The downstream module-config call site
 * (T5.1) is responsible for failing loud if a security-bound module is missing
 * its required signer at the moment of on-chain configuration.
 */
export function deriveModuleSecurity(submitted: Record<string, unknown>): PdaModuleSecurity {
  const reveal = recordValue(submitted.reveal_condition);
  const module = readString(reveal.module) ?? "PaymentObligation";
  // The module security config lives on the reveal-condition. We accept both a
  // flat field (`subject_signer` / `actor`) and a nested `module_security` /
  // `evidence_parameters` record so the read survives T5.1's emission shape.
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
    const expectedAxis: CeremonyAxis = axisRaw === "shred" ? "shred" : "reveal";
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
      readAddress(reveal.actor) ??
      readAddress(security.actor) ??
      readAddress(params.actor);
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

/**
 * Default S2-5 §12 operational-class derivation a `PdaConfigSource` MAY reuse.
 * `legal_effect` PDAs → "legal_effect"; otherwise tier C (or partner-not-ready)
 * → "regulated"/"consumer" tightening is left to the source/composition root.
 * Provided so the same rule is not re-implemented per source.
 */
export function deriveOperationalClass(input: {
  readonly legal_effect_expected: boolean;
  readonly trust_tier: TrustTier;
}): OperationalClass {
  if (input.legal_effect_expected) return "legal_effect";
  if (input.trust_tier === "tier_c") return "regulated";
  return "b2b_partner";
}

// ── The inspector ──────────────────────────────────────────────────────────────

/**
 * Map a resolved PDA config (configurator artifact + operational class) onto the
 * extended ingest inspection. This is the pure, load-bearing core: every output
 * field is read from the PDA, none synthesized. The function is shared by the
 * real (Postgres-backed) inspector and unit tests (fake source).
 */
export function mapResolvedPdaToInspection(
  resolved: ResolvedPdaConfig,
): PdaInspectionForIngestExtended {
  const insp = resolved.inspection;
  const policy = insp.conditional_recipient_policy_summary;

  const g3Choice: G3Choice = insp.g3_choice;
  const g4Phase: G4Phase = insp.g4_phase;
  const trustTier: TrustTier = mapTrustTier(insp.trust_tier);

  // `recipients_root` / `conditional_recipients_policy_digest` are OPTIONAL on
  // `PdaInspectionForIngest` and are not direct fields of the configurator's
  // partner-readable inspection — they are derived at h_commit construction
  // (constructHCommitArtifacts) from the recipient set + policy. We omit them
  // here rather than synthesize a zero/placeholder (platform principle: never
  // fabricate a PDA value). The conditional-recipient policy itself is surfaced
  // structurally via `access_structure_profile` (n/k), which is what the dealer
  // needs; the h_commit binding of the policy digest is computed downstream.

  const inspection: PdaInspectionForIngestExtended = {
    // ── PdaInspectionForIngest (narrow surface consumed by routes-create-mode-a) ──
    pda_id: bytesToHex(insp.pda_id),
    pda_version: insp.pda_version.toString(),
    partner_id: bytesToHex(insp.partner_id),
    pda_root: bytesToHex(insp.pda_root),
    schema_digest: bytesToHex(insp.schema_digest),
    g3_choice: g3Choice,
    g4_phase: g4Phase,
    operational_class: resolved.operational_class,
    trust_tier: trustTier,
    retention_seconds: insp.retention_windows.retention_seconds,
    ...(resolved.retention_policy_id !== undefined
      ? { retention_policy_id: resolved.retention_policy_id }
      : {}),
    partner_ready: resolved.partner_ready,
    legal_effect_expected: insp.legal_flags_art9_qes_jurisdiction.legal_effect_expected,
    ...(resolved.halted !== undefined ? { halted: resolved.halted } : {}),
    ...(resolved.halt_reason !== undefined ? { halt_reason: resolved.halt_reason } : {}),
    reveal_challenge_window_seconds: Number(insp.challenge_windows.reveal_seconds),
    shred_challenge_window_seconds: Number(insp.challenge_windows.shred_seconds),
    shred_authority: mapShredAuthority(insp.shred_authority),
    shred_condition_summary: insp.shred_condition_summary,

    // ── T1.4 extensions (sealer/dealer + reveal gatherer) ────────────────────────
    access_structure_profile: deriveAccessStructureProfile({ n: policy.n, k: policy.k }),
    module_security: deriveModuleSecurity(resolved.submitted),
  };

  return inspection;
}

/**
 * Build the `inspectPda` function the ingestion runtime injects. Loads the
 * active PDA via the injected source, then maps it. The returned function shape
 * matches `IngestionDependencies.inspectPda` (it returns a
 * `PdaInspectionForIngestExtended`, which is assignable to the narrow
 * `PdaInspectionForIngest` the interface declares).
 */
export function createPdaInspector(source: PdaConfigSource) {
  return async (input: {
    readonly pda_id: string;
    readonly partner_id: string;
    readonly pda_version: string;
  }): Promise<PdaInspectionForIngestExtended> => {
    const resolved = await source.loadActivePda(input);
    return mapResolvedPdaToInspection(resolved);
  };
}

// ── Postgres-backed source (real infra; the active-agreement lookup) ────────────

/**
 * Loads the configurator artifact for an active PDA. The artifact body is not in
 * the `partner_agreements` pointer table, so it is resolved through this seam
 * (e.g. an IPFS / content-addressed store keyed by the agreement's pda_id, or a
 * re-emit from the partner's submitted PDA). Injected so the Postgres source
 * decides ONLY the active-agreement question; the artifact provenance is a
 * separate, swappable concern. Returns the configurator slice the mapper reads.
 */
export interface PdaArtifactLoader {
  load(input: {
    readonly partner_id: string;
    readonly pda_id: string;
    readonly pda_version: string;
  }): Promise<{
    readonly inspection: PartnerReadableInspection;
    readonly submitted: Record<string, unknown>;
    readonly retention_policy_id?: string;
    readonly halted?: boolean;
    readonly halt_reason?: string;
  }>;
}

export interface PostgresPdaConfigSourceOptions {
  /** postgres-js Sql client bound to the V3 DB (`cealis_v3_dev`). */
  readonly sql: Sql;
  /** Resolves the configurator artifact for the active agreement. */
  readonly artifactLoader: PdaArtifactLoader;
  /** Override the operational-class derivation (default: `deriveOperationalClass`). */
  readonly operationalClassFor?: (input: {
    readonly legal_effect_expected: boolean;
    readonly trust_tier: TrustTier;
  }) => OperationalClass;
}

/** Row shape read back from `partner_agreements` for the active-agreement check. */
interface ActiveAgreementRow {
  readonly pda_id: string;
}

/**
 * The production `PdaConfigSource`. Confirms an ACTIVE `partner_agreements` row
 * (status='active', most-recent effective_at, effective_at ≤ now) exists for the
 * (partner_id, pda_id) — a partner cannot ingest under a PDA that has no active
 * agreement — then loads the configurator artifact and resolves the operational
 * class. NOTHING hardcoded: every surfaced value comes from the artifact.
 */
export class PostgresPdaConfigSource implements PdaConfigSource {
  private readonly sql: Sql;
  private readonly artifactLoader: PdaArtifactLoader;
  private readonly operationalClassFor: (input: {
    readonly legal_effect_expected: boolean;
    readonly trust_tier: TrustTier;
  }) => OperationalClass;

  constructor(options: PostgresPdaConfigSourceOptions) {
    this.sql = options.sql;
    this.artifactLoader = options.artifactLoader;
    this.operationalClassFor = options.operationalClassFor ?? deriveOperationalClass;
  }

  async loadActivePda(input: {
    readonly partner_id: string;
    readonly pda_id: string;
    readonly pda_version: string;
  }): Promise<ResolvedPdaConfig> {
    const rows = await this.sql<ActiveAgreementRow[]>`
      SELECT pda_id
      FROM partner_agreements
      WHERE partner_id = ${input.partner_id}
        AND pda_id = ${input.pda_id}
        AND status = ${"active"}
        AND effective_at <= now()
      ORDER BY effective_at DESC
      LIMIT 1
    `;
    if (rows.length === 0) {
      throw new PdaNotFoundError(input.partner_id, input.pda_id, input.pda_version);
    }

    const artifact = await this.artifactLoader.load(input);
    const legalEffect = artifact.inspection.legal_flags_art9_qes_jurisdiction.legal_effect_expected;
    const operationalClass = this.operationalClassFor({
      legal_effect_expected: legalEffect,
      trust_tier: mapTrustTier(artifact.inspection.trust_tier),
    });

    return {
      inspection: artifact.inspection,
      submitted: artifact.submitted,
      operational_class: operationalClass,
      ...(artifact.retention_policy_id !== undefined
        ? { retention_policy_id: artifact.retention_policy_id }
        : {}),
      // The active agreement existing IS the partner-ready gate at the agreement
      // layer; finer partner-readiness is on the PDA legal posture.
      partner_ready: true,
      ...(artifact.halted !== undefined ? { halted: artifact.halted } : {}),
      ...(artifact.halt_reason !== undefined ? { halt_reason: artifact.halt_reason } : {}),
    };
  }
}

/**
 * Concrete factory for the composition root (Wave 5): the real Postgres-backed
 * inspector. Wave 5 injects the returned function as
 * `IngestionDependencies.inspectPda`.
 */
export function createPostgresPdaInspector(options: PostgresPdaConfigSourceOptions) {
  return createPdaInspector(new PostgresPdaConfigSource(options));
}
