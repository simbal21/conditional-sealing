import type { SubmittedPda, SyntaxViolation } from "./required-fields.js";
import { isRecord, valueClass } from "./required-fields.js";

const ENUMS: Readonly<Record<string, readonly string[]>> = {
  g3_choice: ["dcipher", "drand"],
  trust_tier: ["A", "B", "C"],
  ingestion_mode: ["ModeA", "ModeB", "A", "B"],
  delivery_mode: ["PASSKEY_ACCOUNT", "DIRECT", "ENCRYPTED_DOWNLOAD", "WALLET_EIP1271"],
  mode: ["P", "F"],
  sd_default: ["cleartext", "zkp", "escrow_only"],
  sd_policy: ["cleartext", "zkp", "escrow_only"],
  shred_authority: ["Subject", "Joint", "Operator", "Timelock", "Disabled"],
};

const BOOLEAN_FIELDS = new Set<string>([
  "art_9_scoped",
  "cealis_class_wide_halt_opt_out",
  "conditional_recipients_updatable",
  "emergency_response_bricking_acknowledgment",
  "legal_effect_expected",
  "mandatory_guardrail_present",
  "partner_ready",
  "pda_updatable",
  "sd_enabled",
  "subject_liveness_required_at_fire",
  "time_critical_pda_flag",
  "versioned_migration_ceremony",
]);

function enumAllowed(path: string): readonly string[] | null {
  const tail = path.split(".").at(-1);
  if (tail === undefined) return null;
  if (tail.endsWith("delivery_mode")) return ENUMS.delivery_mode ?? null;
  if (tail.endsWith("sd_policy") || tail === "sd_default") return ENUMS.sd_policy ?? null;
  return ENUMS[tail] ?? null;
}

function walk(value: unknown, path: string, failures: SyntaxViolation[]): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      walk(entry, `${path}[${String(index)}]`, failures);
    });
    return;
  }

  if (!isRecord(value)) return;

  for (const [key, child] of Object.entries(value)) {
    const childPath = path.length === 0 ? key : `${path}.${key}`;
    const allowed = enumAllowed(childPath);
    if (allowed !== null && typeof child === "string" && !allowed.includes(child)) {
      failures.push({
        surface_name: "enum_mapping_valid",
        code: "UNKNOWN_ENUM_IDENTIFIER",
        source_field_path: childPath,
        failed_predicate: `${childPath} maps to a known enum identifier`,
        sanitized_value_class: `enum_string_${child}`,
        partner_friendly_field_label: childPath,
        why_failed: `This deployment uses ${child} for ${childPath}, but that enum identifier is not known to the configurator.`,
        partner_action_text: `Choose one of: ${allowed.join(", ")}.`,
      });
    }
    if (BOOLEAN_FIELDS.has(key) && typeof child !== "boolean") {
      failures.push({
        surface_name: "enum_mapping_valid",
        code: "BOOLEAN_TYPE_INVALID",
        source_field_path: childPath,
        failed_predicate: `${childPath} is boolean`,
        sanitized_value_class: valueClass(child),
        partner_friendly_field_label: childPath,
        why_failed: `This deployment uses a non-boolean value for ${childPath}.`,
        partner_action_text: `Set ${childPath} to true or false.`,
      });
    }
    walk(child, childPath, failures);
  }
}

export function checkEnumMapping(pda: SubmittedPda): readonly SyntaxViolation[] {
  const failures: SyntaxViolation[] = [];
  walk(pda, "", failures);
  return failures;
}
