import { createHash } from "node:crypto";

export interface TemplateEmission {
  readonly template_id: string;
  readonly contentHash: string;
  readonly canonical_bytes: string;
}

function canonicalJson(value: unknown): string {
  const normalized = normalize(value);
  const serialized = JSON.stringify(normalized);
  if (serialized === undefined) {
    throw new Error("Template canonicalization failed");
  }
  return serialized;
}

function normalize(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map((entry) => normalize(entry));
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      out[key] = normalize(record[key]);
    }
    return out;
  }
  return null;
}

export function emitContentAddressedTemplate(
  template: unknown,
): TemplateEmission {
  const canonical = canonicalJson(template);
  const contentHash = `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
  return { template_id: contentHash, contentHash, canonical_bytes: canonical };
}

export function assertTemplateBytesUnchanged(
  previous: TemplateEmission,
  nextTemplate: unknown,
): TemplateEmission {
  const next = emitContentAddressedTemplate(nextTemplate);
  if (
    previous.template_id === next.template_id &&
    previous.canonical_bytes !== next.canonical_bytes
  ) {
    throw new Error(
      "No implementation may mutate canonical bytes under an existing template_id",
    );
  }
  return next;
}
