const FORBIDDEN_MANIFEST_KEY = /(?:plaintext|shamir|share|dek|file_key|sigma_bytes|decap|secret)/i;

export function sanitizeManifestValue(value: unknown, depth = 0): unknown {
  if (depth > 16) return "[REDACTED:depth_limit]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map((item) => sanitizeManifestValue(item, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_MANIFEST_KEY.test(key)) continue;
      out[key] = sanitizeManifestValue(inner, depth + 1);
    }
    return out;
  }
  return undefined;
}

export function assertManifestContainsNoShareMaterial(value: unknown): void {
  const text = JSON.stringify(value);
  if (text === undefined) return;
  if (FORBIDDEN_MANIFEST_KEY.test(text)) {
    throw new Error("CombinerManifest contains forbidden share/plaintext/DEK material.");
  }
}
