import type { SubmittedPda, SyntaxViolation } from "./required-fields.js";
import { hasOwn, valueClass } from "./required-fields.js";

const ALLOWED_TOP_LEVEL_FIELDS = new Set<string>([
  "schema_version",
  "schema_version_allows_extension_metadata",
  "extension_metadata",
  "pda_id",
  "pda_version",
  "partner_id",
  "template_id",
  "template_name",
  "template",
  "schema",
  "schema_mapping",
  "schema_digest",
  "commit_version",
  "versioned_migration_ceremony",
  "pda_root_fields",
  "pda_root_extra_fields",
  "commit_aad_fields",
  "sdMerkleRoot",
  "sd_enabled",
  "sd_plan",
  "sd_field_policies",
  "ingestion_mode",
  "delivery_mode",
  "delivery_modes",
  "evidence_cid",
  "recipients",
  "conditional_recipients",
  "global_shamir_threshold",
  "fixed_gates",
  "g3_choice",
  "g4_phase",
  "phase",
  "g4_phase_semantics",
  "phase_1_claim",
  "lit_vendor_family",
  "g4_vendor_family",
  "gate_recipient_pubkeys",
  "registry_lookup_mode",
  "historical_registry_lookup",
  "reveal_condition",
  "shred_condition",
  "reveal_shred_axes_separated",
  "reveal_authorization_sources",
  "legal_effect_expected",
  "partner_ready",
  "cealis_class_wide_halt_opt_out",
  "trust_tier",
  "use_case",
  "archetype",
  "retention_seconds",
  "minimum_shred_latency_seconds",
  "reveal_challenge_window_seconds",
  "shred_challenge_window_seconds",
  "fire_time_ttl_estimate_seconds",
  "sigma_usage",
  "sigma_handling",
  "dek_lifecycle",
  "wraps_full_dek_to_single_gate",
  "disclosure_registry_authorizes_reveal",
]);

function allowsExtensionMetadata(pda: SubmittedPda): boolean {
  return pda["schema_version_allows_extension_metadata"] === true;
}

function isExtensionField(field: string): boolean {
  return field === "extension_metadata" || field.startsWith("x_");
}

export function checkUnknownFields(pda: SubmittedPda): readonly SyntaxViolation[] {
  const failures: SyntaxViolation[] = [];
  const extensionAllowed = allowsExtensionMetadata(pda);
  for (const field of Object.keys(pda).sort()) {
    if (ALLOWED_TOP_LEVEL_FIELDS.has(field)) continue;
    if (extensionAllowed && isExtensionField(field)) continue;
    const predicate = extensionAllowed
      ? `${field} is a declared extension metadata field`
      : `${field} is in the S2-4 submitted PDA schema`;
    failures.push({
      surface_name: "unknown_fields_rejected",
      code: "UNKNOWN_FIELD",
      source_field_path: field,
      failed_predicate: predicate,
      sanitized_value_class: hasOwn(pda, field) ? valueClass(pda[field]) : "missing",
      partner_friendly_field_label: field,
      why_failed: `This deployment includes ${field}, which is not part of the accepted PDA submission shape.`,
      partner_action_text: "Remove the field or route it through explicit extension metadata.",
    });
  }
  return failures;
}
