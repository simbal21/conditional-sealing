import type { SubmittedPda, SyntaxViolation } from "./required-fields.js";
import { isRecord, valueClass } from "./required-fields.js";

const CID_V1_BASE32 = /^b[a-z2-7]{20,}$/;

function shouldCheckCid(key: string): boolean {
  return key === "cid" || key.endsWith("_cid") || key.endsWith("_cids") || key.includes("ipfs");
}

function checkOne(value: unknown, path: string, failures: SyntaxViolation[]): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => checkOne(entry, `${path}[${String(index)}]`, failures));
    return;
  }
  if (typeof value === "string" && !CID_V1_BASE32.test(value)) {
    failures.push({
      surface_name: "cid_parse",
      code: "CID_PARSE_FAILED",
      source_field_path: path,
      failed_predicate: `${path} parses as CIDv1 base32`,
      sanitized_value_class: valueClass(value),
      partner_friendly_field_label: path,
      why_failed: `This deployment includes an IPFS/CID reference at ${path}, but the CID does not parse as the expected base32 form.`,
      partner_action_text: "Provide a CIDv1 base32 value, or remove the CID reference until pinning occurs.",
    });
  }
}

function walk(value: unknown, path: string, key: string, failures: SyntaxViolation[]): void {
  if (shouldCheckCid(key)) {
    checkOne(value, path, failures);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walk(entry, `${path}[${String(index)}]`, key, failures));
    return;
  }
  if (isRecord(value)) {
    for (const [childKey, child] of Object.entries(value)) {
      const childPath = path.length === 0 ? childKey : `${path}.${childKey}`;
      walk(child, childPath, childKey, failures);
    }
  }
}

export function checkCidParse(pda: SubmittedPda): readonly SyntaxViolation[] {
  const failures: SyntaxViolation[] = [];
  walk(pda, "", "", failures);
  return failures;
}
