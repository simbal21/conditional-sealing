// S2-4 §1.3 + §4.7 — Dual-form error message contract.
//
// Every validation failure emits BOTH an internal audit form AND a
// partner-facing form. The two forms share the stage-indexed error code
// from `stage-codes.ts` but expose different field sets.
//
// Phase A locks the interface shapes. Phase B-E implementations construct
// dual-form instances at every Stage 1-4 rejection point (Stage 5
// failures route through human-review surface and produce their own
// rendering).
//
// SPEC-COMPLIANCE-GUARD §7: every dual-form instance must have BOTH
// forms; emitting only the internal form (or only the partner-facing
// form) is non-conformant.

import type { CfCode } from "../types/cf-codes.js";
import type { CiCode } from "../types/ci-codes.js";
import type { Category, SubClass } from "../types/categories.js";
import type { Stage } from "./stage-codes.js";

/**
 * Internal audit form per §1.3.
 *
 * All fields are required for new-style rejections. Legacy callers may
 * pass `null` where a field is genuinely not applicable (e.g.,
 * `governance_sub_class` for category (b)/(c)/(d) rejections).
 */
export interface InternalErrorForm {
  /** Stage that owned the primary rejection (1..5 per §4.1). */
  readonly stage: Stage;
  /** Stable snake_case surface name from class-table row. */
  readonly surface_name: string;
  /**
   * Failed predicate in compact prose form (e.g., "k > n",
   * "post_challenge_reveal_in_progress not present in guardrail").
   */
  readonly failed_predicate: string;
  /** Category of the failed surface per §3 / §5.2. */
  readonly category: Category;
  /** Governance sub-class for category (a) surfaces; null otherwise. */
  readonly governance_sub_class: SubClass | null;
  /**
   * Source field path within the submitted PDA JSON (dot-separated).
   * Example: `recipients[2].delivery_mode`.
   */
  readonly source_field_path: string;
  /**
   * Sanitized value class — NOT the raw PII value.
   *
   * Examples: `"boolean_true"`, `"enum_value_dcipher"`,
   * `"bytes32_hex_zeroed"`, `"uint64_in_bounds"`. Sanitization is
   * mandatory per §1.3.
   */
  readonly sanitized_value_class: string;
  /**
   * Relevant cross-references to other Stage-2 specs in free-form prose.
   * Example: `"WP §F Art.22 guardrail; S2-1 §3.3.4; S2-2 App.A PdaRootFields"`.
   */
  readonly cross_references: string;
  /**
   * Remediation path: adjust PDA value, request PDA+ expansion, or
   * impossible-under-V2.
   */
  readonly remediation: "adjust_pda_value" | "request_pda_plus_expansion" | "impossible_under_v2";
  /**
   * Human-readable remediation guidance (free-form prose for operator
   * audit notes).
   */
  readonly remediation_text: string;
  /**
   * Originating CI code (Stage 2) or CF code (Stage 4) when applicable.
   * Stage 1 / 3 / 5 do not have catalog codes; this field is null for
   * those stages.
   */
  readonly originating_ci_code: CiCode | null;
  readonly originating_cf_code: CfCode | null;
}

/**
 * Partner-facing form per §1.3.
 *
 * Per §14.4: "Partner-facing validation copy must say which intent
 * failed, not expose internal taxonomy alone. It must not overclaim.
 * Use outcome-language."
 */
export interface PartnerFacingErrorForm {
  /** Stage-indexed code from `formatStageCode()` — same as internal form. */
  readonly stage_code: string;
  /**
   * Field or concept that failed in partner-friendly language.
   * Example: "Halt opt-out flag" (NOT `cealis_class_wide_halt_opt_out`).
   */
  readonly partner_friendly_field_label: string;
  /**
   * Outcome-language explanation per §14.4. Examples:
   *   - "This configuration would allow a shred after gate signing
   *      starts; Cealis rejects that because shred cannot race an
   *      authorized reveal."
   *   - "This deployment expects legal effects, so it cannot opt out
   *      of Cealis's class-wide halt safety path. Set halt opt-out to
   *      false, or run a separate non-legal-effect deployment."
   */
  readonly why_failed: string;
  /**
   * Whether the partner can choose a different allowed option, or
   * must request a Cealis-internal PDA+ change.
   */
  readonly partner_action: "choose_different_allowed_option" | "request_pda_plus_change";
  /**
   * Concrete action text (e.g., "Set halt opt-out to false" or
   * "Request a new Tier-A oracle entry via Cealis BD").
   */
  readonly partner_action_text: string;
}

/**
 * Combined dual-form record emitted per validation rejection.
 *
 * Phase B/C/D/E constructors MUST populate BOTH forms — emitting only
 * the internal form is non-conformant per SPEC-COMPLIANCE-GUARD §7.
 */
export interface DualFormValidationFailure {
  readonly stage_code: string;
  readonly internal: InternalErrorForm;
  readonly partner_facing: PartnerFacingErrorForm;
}
