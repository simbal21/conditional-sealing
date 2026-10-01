import * as canonicalizeModule from "canonicalize";
import { keccak_256 } from "@noble/hashes/sha3";
import type {
  Hex,
  Hex32,
  RevealArtifactBundle,
  VerifyArtifactOptions,
  VerifyCheck,
} from "../types.js";

export type CheckContext = {
  readonly options: VerifyArtifactOptions;
  readonly now: Date;
};

export type ArtifactCheckResult = {
  readonly check: VerifyCheck;
  readonly artifactBundleDigest?: Hex32;
};

type JcsValue =
  | null
  | boolean
  | number
  | string
  | readonly JcsValue[]
  | { readonly [key: string]: JcsValue };

const canonicalizeJson = (canonicalizeModule as unknown as {
  readonly default: (input: unknown) => string | undefined;
}).default;

export const ZERO_HEX32 = `0x${"0".repeat(64)}` as Hex32;

export const REVEAL_ARTIFACT_BUNDLE_TOP_KEYS = [
  "bundle_version",
  "canonicalization",
  "authorization",
  "pda",
  "recipient",
  "plaintext",
  "issuer_attestation",
  "provenance",
  "sigma_block",
  "chain_proofs",
  "registry_snapshots",
  "shred_state",
  "sd_refs",
  "verification",
  "pii_statement",
] as const;

const HEX_PATTERN = /^0x[0-9a-fA-F]*$/;
const HEX32_PATTERN = /^0x[0-9a-fA-F]{64}$/;

const SAFE_REF_KEYS = new Set([
  "authorizationId",
  "h_commit",
  "pda_root",
  "authorization_block",
  "authorization_block_hash",
  "block_number",
  "block_hash",
  "log_index",
  "registry_ref",
  "pda_id",
  "partner_id",
  "artifact_digest",
  "event_id",
  "encrypted_diagnostic_ref",
]);

export function passCheck(code: string, safeRefs?: Record<string, unknown>): VerifyCheck {
  return { status: "pass", code, safe_refs: safeRefsOnly(safeRefs) };
}

export function failCheck(
  code: string,
  message: string,
  safeRefs?: Record<string, unknown>,
): VerifyCheck {
  return { status: "fail", code, message, safe_refs: safeRefsOnly(safeRefs) };
}

export function skippedCheck(code: string, safeRefs?: Record<string, unknown>): VerifyCheck {
  return { status: "skipped", code, safe_refs: safeRefsOnly(safeRefs) };
}

export function safeRefsOnly(
  input?: Record<string, unknown>,
): Record<string, string | number | boolean> | undefined {
  if (input === undefined) return undefined;
  const out: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(input)) {
    if (!SAFE_REF_KEYS.has(key)) continue;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
    }
  }
  return Object.keys(out).length === 0 ? undefined : out;
}

export function safeRefsFromBundle(bundle: RevealArtifactBundle): Record<string, unknown> {
  return {
    authorizationId: bundle.authorization.authorizationId,
    h_commit: bundle.authorization.h_commit,
    pda_root: bundle.pda.pda_root,
    authorization_block: bundle.authorization.authorization_block,
    authorization_block_hash: bundle.authorization.authorization_block_hash,
    pda_id: bundle.pda.pda_id,
    artifact_digest: bundle.verification.artifact_bundle_digest,
  };
}

export function isHex(value: unknown): value is Hex {
  return typeof value === "string" && HEX_PATTERN.test(value);
}

export function isHex32(value: unknown): value is Hex32 {
  return typeof value === "string" && HEX32_PATTERN.test(value);
}

export function normalizeHex32(value: Hex32): Hex32 {
  return `0x${value.slice(2).toLowerCase()}` as Hex32;
}

export function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function unknownArray(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

export function requiredString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

export function toJcsValue(value: unknown): JcsValue {
  if (value === null) return null;
  if (typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS value cannot contain non-finite numbers.");
    return value;
  }
  if (Array.isArray(value)) return value.map((inner) => toJcsValue(inner));
  if (typeof value === "object") {
    const out: Record<string, JcsValue> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      if (inner !== undefined) out[key] = toJcsValue(inner);
    }
    return out;
  }
  throw new Error(`JCS value cannot contain ${typeof value}.`);
}

export function canonicalizeJcsString(value: unknown): string {
  const encoded = canonicalizeJson(toJcsValue(value));
  if (encoded === undefined) throw new Error("JCS canonicalization failed.");
  return encoded;
}

export function bytesToHex(bytes: Uint8Array): Hex {
  let hex = "0x";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex as Hex;
}

export function bytesToHex32(bytes: Uint8Array): Hex32 {
  if (bytes.length !== 32) throw new Error(`expected 32 bytes, got ${bytes.length}`);
  return bytesToHex(bytes) as Hex32;
}

export function jcsDigestHex32(value: unknown): Hex32 {
  return normalizeHex32(bytesToHex32(keccak_256(new TextEncoder().encode(canonicalizeJcsString(value)))));
}

export function bundleWithZeroDigest(bundle: RevealArtifactBundle): RevealArtifactBundle {
  return {
    ...bundle,
    verification: {
      ...bundle.verification,
      artifact_bundle_digest: ZERO_HEX32,
    },
  };
}

export function computeArtifactBundleDigest(bundle: RevealArtifactBundle): Hex32 {
  return jcsDigestHex32(bundleWithZeroDigest(bundle));
}

export function checkCanonicalization(bundle: RevealArtifactBundle): ArtifactCheckResult {
  const refs = safeRefsFromBundle(bundle);
  try {
    const actualKeys = Object.keys(bundle);
    const expectedKeys = [...REVEAL_ARTIFACT_BUNDLE_TOP_KEYS];
    const topLevelMatches =
      actualKeys.length === expectedKeys.length &&
      actualKeys.every((key, index) => key === expectedKeys[index]);
    if (!topLevelMatches) {
      return {
        check: failCheck("CANONICALIZATION.TOP_LEVEL_KEY_DRIFT", "RevealArtifactBundle top-level keys drifted.", refs),
      };
    }
    if (
      bundle.bundle_version !== "s2-5.1" ||
      bundle.pii_statement !== "recipient_filtered_plaintext_after_valid_reveal" ||
      bundle.canonicalization.format !== "JCS" ||
      bundle.canonicalization.rfc !== "RFC8785" ||
      bundle.canonicalization.hash !== "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))"
    ) {
      return {
        check: failCheck("CANONICALIZATION.MARKER_MISMATCH", "Bundle version or canonicalization marker is invalid.", refs),
      };
    }

    const digest = computeArtifactBundleDigest(bundle);
    const secondDigest = computeArtifactBundleDigest(bundle);
    if (digest !== secondDigest) {
      return {
        check: failCheck("CANONICALIZATION.NON_DETERMINISTIC", "JCS digest changed across repeated runs.", refs),
        artifactBundleDigest: digest,
      };
    }
    if (normalizeHex32(bundle.verification.artifact_bundle_digest) !== digest) {
      return {
        check: failCheck("CANONICALIZATION.DIGEST_MISMATCH", "Artifact bundle digest does not match JCS digest.", refs),
        artifactBundleDigest: digest,
      };
    }
    return {
      check: passCheck("CANONICALIZATION.PASS", refs),
      artifactBundleDigest: digest,
    };
  } catch (error) {
    return {
      check: failCheck(
        "CANONICALIZATION.ERROR",
        error instanceof Error ? error.message : "Canonicalization failed.",
        refs,
      ),
    };
  }
}
