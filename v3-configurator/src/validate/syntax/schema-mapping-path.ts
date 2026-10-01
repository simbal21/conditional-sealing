import type { SubmittedPda, SyntaxViolation } from "./required-fields.js";
import { isRecord, valueClass } from "./required-fields.js";

function collectSchemaPaths(schema: unknown): ReadonlySet<string> {
  const paths = new Set<string>();
  if (!isRecord(schema)) return paths;
  const fields = schema["fields"];
  if (Array.isArray(fields)) {
    for (const field of fields) {
      if (typeof field === "string") {
        paths.add(field);
      } else if (isRecord(field) && typeof field["path"] === "string") {
        paths.add(field["path"]);
      } else if (isRecord(field) && typeof field["name"] === "string") {
        paths.add(field["name"]);
      }
    }
  } else if (isRecord(fields)) {
    for (const key of Object.keys(fields)) {
      paths.add(key);
    }
  }
  return paths;
}

function collectReferencedPaths(schemaMapping: unknown): readonly string[] {
  if (schemaMapping === undefined) return [];
  if (Array.isArray(schemaMapping)) {
    return schemaMapping.filter((entry): entry is string => typeof entry === "string");
  }
  if (!isRecord(schemaMapping)) return [];
  return Object.values(schemaMapping).filter((entry): entry is string => typeof entry === "string");
}

export function checkSchemaMappingPath(pda: SubmittedPda): readonly SyntaxViolation[] {
  const schemaPaths = collectSchemaPaths(pda["schema"]);
  const references = collectReferencedPaths(pda["schema_mapping"]);
  const failures: SyntaxViolation[] = [];
  for (const reference of references) {
    if (!schemaPaths.has(reference)) {
      failures.push({
        surface_name: "schema_mapping_path_resolves",
        code: "SCHEMA_PATH_UNRESOLVED",
        source_field_path: "schema_mapping",
        failed_predicate: `${reference} resolves to submitted schema`,
        sanitized_value_class: valueClass(reference),
        partner_friendly_field_label: reference,
        why_failed: `This deployment maps ${reference}, but that field path is not present in the submitted schema.`,
        partner_action_text: "Use a field path that exists in the schema, or add the field to the schema first.",
      });
    }
  }
  return failures;
}
