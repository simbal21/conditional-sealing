// Per-PDA-tier API behavior table — verbatim from S2-5 §12 (lines 1077-1098).
//
// LOCKED at Phase A. NORMATIVE per §12 line 1077.
// Spec body grep-verified 2026-05-11: 12 behavior axes × 4 operational classes.
// Phase A foundation test asserts 12 rows × 4 cols.
//
// This is the LARGEST single drift catch in PHASE-PLAN §0 sanity check —
// the original single-shot brief omitted §12 entirely. SPEC-COMPLIANCE-GUARD
// §5 records.

/**
 * 4 operational classes (§12 line 1081). A PDA has both a trust tier (A/B/C from
 * S2-4 §4.1) and an operational class. Where they conflict, the STRICTER
 * API behavior applies.
 */
export const OPERATIONAL_CLASSES = ["consumer", "b2b_partner", "regulated", "legal_effect"] as const;
export type OperationalClass = (typeof OPERATIONAL_CLASSES)[number];

/**
 * 12 behavior axes (§12 lines 1083-1096). Phase B/C/D enforce per-axis at
 * the surfaces named in PHASE-PLAN per-chunk dependency lists.
 */
export const TIER_BEHAVIOR_AXES = [
  "g4_phase", // §12 line 1085
  "b2b_ingestion", // §12 line 1086
  "subject_auth", // §12 line 1087
  "preflight_attestation", // §12 line 1088
  "combiner_context", // §12 line 1089
  "webhook_payloads", // §12 line 1090
  "sd_cleartext", // §12 line 1091
  "retention_floor", // §12 line 1092
  "shred_request_auth", // §12 line 1093
  "challenge_windows", // §12 line 1094
  "artifact_verification", // §12 line 1095
  "audit_export", // §12 line 1096
] as const;

export type TierBehaviorAxis = (typeof TIER_BEHAVIOR_AXES)[number];

export const TIER_BEHAVIOR_AXIS_COUNT: number = TIER_BEHAVIOR_AXES.length;
export const TIER_BEHAVIOR_CLASS_COUNT: number = OPERATIONAL_CLASSES.length;

/**
 * 12 × 4 NORMATIVE matrix — verbatim from §12 table prose.
 *
 * Format: `TIER_BEHAVIOR_MATRIX[axis][class] = prose_descriptor`.
 *
 * NOTE: prose is the spec body verbatim, not a paraphrase. Phase B/C/D consult
 * this matrix to decide per-class API strictness; they do NOT paraphrase the
 * prose into custom enum values inside route handlers.
 */
export const TIER_BEHAVIOR_MATRIX: Readonly<
  Record<TierBehaviorAxis, Readonly<Record<OperationalClass, string>>>
> = {
  g4_phase: {
    consumer: "Phase 2 preferred; Phase 1 only if non-partner-ready dev-scaffold",
    b2b_partner: "Phase 2",
    regulated: "Phase 2 required",
    legal_effect: "Phase 2 required",
  },
  b2b_ingestion: {
    consumer: "Not applicable",
    b2b_partner: "allowed if PDA submitter set permits",
    regulated: "mTLS required",
    legal_effect: "mTLS required + legal packet ref",
  },
  subject_auth: {
    consumer: "Passkey/WebAuthn",
    b2b_partner: "Passkey where subject signs",
    regulated: "Passkey or QTSP as configured",
    legal_effect: "QTSP when qes_subject_required true",
  },
  preflight_attestation: {
    consumer: "mandatory four checks",
    b2b_partner: "mandatory four checks",
    regulated: "mandatory four checks + audit transcript",
    legal_effect: "mandatory four checks + retained audit transcript",
  },
  combiner_context: {
    consumer: "audited process memory permitted with warning",
    b2b_partner: "recipient server or delegated service",
    regulated: "recipient-controlled TEE/HSM or equivalent sandbox",
    legal_effect: "TEE/HSM plus artifact audit packet",
  },
  webhook_payloads: {
    consumer: "status refs only",
    b2b_partner: "lifecycle refs",
    regulated: "lifecycle refs + encrypted diagnostics",
    legal_effect: "lifecycle refs + encrypted diagnostics",
  },
  sd_cleartext: {
    consumer: "subject-visible only where configured",
    b2b_partner: "partner receives configured fields",
    regulated: "ZK-opened cleartext preferred",
    legal_effect: "ZK-opened or counsel-approved",
  },
  retention_floor: {
    consumer: "PDA-specific",
    b2b_partner: "obligation + 3 years default where obligations apply",
    regulated: "legal/regulatory floor",
    legal_effect: "legal/counsel floor",
  },
  shred_request_auth: {
    consumer: "subject if allowed",
    b2b_partner: "partner/joint/operator if allowed",
    regulated: "joint/operator controls often required",
    legal_effect: "counsel-reviewed authority",
  },
  challenge_windows: {
    consumer: "PDA trust tier controls",
    b2b_partner: "PDA trust tier controls",
    regulated: "Tier B/C floors enforced",
    legal_effect: "Tier B/C plus Art. 22 safeguards",
  },
  artifact_verification: {
    consumer: "SDK recommended",
    b2b_partner: "SDK required before use",
    regulated: "SDK required with stored verification result",
    legal_effect: "SDK required with verification packet",
  },
  audit_export: {
    consumer: "subject self-service",
    b2b_partner: "partner scoped",
    regulated: "partner + auditor scoped",
    legal_effect: "partner + auditor + legal packet scoped",
  },
} as const;

/**
 * Universal tripwire — §12 final paragraph (line 1098):
 *   "No tier may bypass the universal tripwire. Tiers change attestation
 *    strictness, combiner execution context, retention, challenge posture,
 *    and audit packaging; they do not create alternate release conditions."
 *
 * Phase A locks this as a string constant so any guard sheet or test
 * referring to it cites the same wording.
 */
export const UNIVERSAL_TRIPWIRE_STATEMENT =
  "No tier may bypass the universal tripwire. Tiers change attestation strictness, combiner execution context, retention, challenge posture, and audit packaging; they do not create alternate release conditions.";

/**
 * Trust tier (S2-4 §4.1) — orthogonal to operational class. Both appear on every
 * PDA. Where they conflict, stricter API behavior applies (§12 line 1081).
 */
export const TRUST_TIERS = ["tier_a", "tier_b", "tier_c"] as const;
export type TrustTier = (typeof TRUST_TIERS)[number];
