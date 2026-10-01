import type { SubmittedPda, SyntaxViolation } from "./required-fields.js";
import { isRecord, valueClass } from "./required-fields.js";

const BYTES32_HEX = /^0x[0-9a-fA-F]{64}$/;
const BYTES32_KEY_PATTERN = /(^pda_id$|_hash$|_root$|_digest$|_ref$|_id$)/;
const NON_BYTES32_ID_KEYS = new Set<string>(["schema_version", "template_name", "partner_id"]);

function shouldCheckKey(key: string): boolean {
  if (NON_BYTES32_ID_KEYS.has(key)) return false;
  return BYTES32_KEY_PATTERN.test(key);
}

function walk(value: unknown, path: string, key: string, failures: SyntaxViolation[]): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      walk(entry, `${path}[${String(index)}]`, key, failures);
    });
    return;
  }
  if (isRecord(value)) {
    for (const [childKey, child] of Object.entries(value)) {
      const childPath = path.length === 0 ? childKey : `${path}.${childKey}`;
      walk(child, childPath, childKey, failures);
    }
    return;
  }
  if (typeof value === "string" && shouldCheckKey(key) && !BYTES32_HEX.test(value)) {
    failures.push({
      surface_name: "bytes32_hex_format",
      code: "BYTES32_HEX_INVALID",
      source_field_path: path,
      failed_predicate: `${path} is a 32-byte 0x-prefixed hex string`,
      sanitized_value_class: valueClass(value),
      partner_friendly_field_label: path,
      why_failed: `This deployment uses a digest-like value for ${path}, but it is not a 32-byte hex string.`,
      partner_action_text: `Provide ${path} as 0x followed by 64 hex characters.`,
    });
  }
}

export function isBytes32Hex(value: unknown): value is string {
  return typeof value === "string" && BYTES32_HEX.test(value);
}

export function checkBytes32Hex(pda: SubmittedPda): readonly SyntaxViolation[] {
  const failures: SyntaxViolation[] = [];
  walk(pda, "", "", failures);
  return failures;
}
