import type { FastifyInstance, preHandlerHookHandler } from "fastify";
import {
  REVEAL_ARTIFACT_BUNDLE_TOP_KEYS,
  VERIFY_ARTIFACT_CHECK_NAMES,
  type VerifyStatus,
} from "../types/reveal-artifact-bundle.js";
import type { OperationId } from "../types/operation-ids.js";

export interface VerifyRouteContext {
  readonly preHandlers?: (operationId: OperationId) => preHandlerHookHandler[];
}

export interface VerifyArtifactRequest {
  readonly bundle: Record<string, unknown>;
  /**
   * Partner MUST explicitly set this to acknowledge that the server-side endpoint
   * is structural-only and is NOT a cryptographic verification. Without this flag
   * the endpoint refuses to return `overall: "pass"` — preventing accidental
   * partner reliance on a fake-pass. Security-audit-2026-05-14 TS-API-F-06.
   *
   * For enforcement-grade verification, partners MUST run @cealis/verify-sdk
   * locally (no server in the trust path) — see verify-sdk README.
   */
  readonly acknowledge_structural_only?: boolean;
}

export function verifyArtifactBundleServerSide(request: VerifyArtifactRequest): Record<string, unknown> {
  const missing = REVEAL_ARTIFACT_BUNDLE_TOP_KEYS.filter((key) => request.bundle[key] === undefined);
  const refs = safeRefsFromBundle(request.bundle);

  // Security-audit-2026-05-14 TS-API-F-06 hardening:
  // The previous implementation returned `overall: "pass"` if every top-level
  // key was present — pure structural cross-check, no cryptographic verification.
  // A partner that called this endpoint and trusted its result would accept
  // forged bundles whose hex fields all parse but whose signatures are invalid.
  //
  // The endpoint is retained for structural-only debugging (e.g., schema-shape
  // CI checks) BUT now:
  //   1. refuses to return `pass` unless the caller explicitly opts-in via
  //      `acknowledge_structural_only: true`
  //   2. always sets `sdk_replacement: false`
  //   3. embeds a warning string in the response
  //   4. fails closed (`overall: "fail"`) on the no-opt-in path
  //
  // Partners performing enforcement-grade verification MUST use the
  // @cealis/verify-sdk locally — server endpoint cannot substitute (the server
  // sits in the trust path) and the SDK exposes the full 16-check pipeline
  // including freshness, chain-proof receipt verification, and per-stanza σ
  // recovery against on-chain pubkey snapshots.

  if (request.acknowledge_structural_only !== true) {
    return {
      implementation: "server_side_structural_cross_check",
      sdk_replacement: false,
      overall: "fail" as VerifyStatus,
      warning:
        "Server-side endpoint is STRUCTURAL-ONLY (key-presence check). It is NOT a cryptographic " +
        "verification. Set `acknowledge_structural_only: true` to opt in to the structural check, " +
        "OR run @cealis/verify-sdk locally for enforcement-grade verification.",
      missing_top_level_keys: missing,
      checks: Object.fromEntries(
        VERIFY_ARTIFACT_CHECK_NAMES.map((name) => [
          name,
          {
            status: "fail" as VerifyStatus,
            code: "STRUCTURAL_ONLY_NOT_ACKNOWLEDGED",
            safe_refs: refs,
          },
        ]),
      ),
    };
  }

  const overall: VerifyStatus = missing.length === 0 ? "pass" : "fail";
  const checks = Object.fromEntries(
    VERIFY_ARTIFACT_CHECK_NAMES.map((name) => [
      name,
      {
        status: overall,
        code: missing.length === 0 ? "STRUCTURAL_CHECK_PRESENT" : "STRUCTURAL_CHECK_MISSING_TOP_LEVEL_KEY",
        safe_refs: refs,
      },
    ]),
  );
  return {
    implementation: "server_side_structural_cross_check",
    sdk_replacement: false,
    warning:
      "Structural-only check passed key-presence. This is NOT a cryptographic verification — " +
      "use @cealis/verify-sdk locally for enforcement-grade results.",
    overall,
    missing_top_level_keys: missing,
    checks,
  };
}

export function registerVerifyArtifactBundleRoute(app: FastifyInstance, context: VerifyRouteContext): void {
  app.post<{ Body: VerifyArtifactRequest }>(
    "/v1/verify/artifact-bundles",
    { preHandler: context.preHandlers?.("verifyArtifactBundle") },
    async (request) => verifyArtifactBundleServerSide(request.body),
  );
}

function safeRefsFromBundle(bundle: Record<string, unknown>): Record<string, string> {
  const authorization = recordValue(bundle.authorization);
  const pda = recordValue(bundle.pda);
  const verification = recordValue(bundle.verification);
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries({
    authorizationId: authorization.authorizationId,
    h_commit: authorization.h_commit,
    pda_id: pda.pda_id,
    artifact_digest: verification.artifact_bundle_digest,
  })) {
    if (typeof value === "string") out[key] = value;
  }
  return out;
}

function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}
