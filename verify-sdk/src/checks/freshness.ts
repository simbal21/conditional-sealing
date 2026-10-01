import type { RevealArtifactBundle, VerifyCheck } from "../types.js";
import type { CheckContext } from "./canonicalization.js";
import { failCheck, passCheck, safeRefsFromBundle, skippedCheck } from "./canonicalization.js";

/**
 * Artifact-bundle freshness check.
 *
 * Without this, an artifact bundle valid at delivery time stays verify=pass forever:
 * an attacker who captured a legitimate bundle can replay it back to a partner months
 * later and pass all structural checks. Security-audit-2026-05-14 TS-API-F-03.
 *
 * **R2b-3 closure (2026-05-21): freshness is DEFAULT-ON.** The pre-R2b-3 behavior
 * (skip when `maxArtifactAgeSeconds` is undefined and silently rely on the caller to
 * enforce out-of-band) was the F-08-class opt-in defect: callers who forgot the
 * option got NO freshness enforcement, and the check returned `skipped` which the
 * orchestrator would happily aggregate as overall-pass. Now:
 *
 * - **Default-on:** `maxArtifactAgeSeconds === undefined` → enforce a 24-hour
 *   (86_400s) window. `finalized_at > 24h ago` ⇒ FAIL (`FRESHNESS.STALE`).
 * - **Caller override:** `maxArtifactAgeSeconds === N` → enforce N-seconds window.
 * - **Explicit opt-OUT:** `disableFreshnessCheck === true` → return `skipped`
 *   with sub-code `FRESHNESS.SKIPPED_EXPLICIT_OPT_OUT`. Caller MUST have set the
 *   flag explicitly; omitting it does NOT skip.
 *
 * `finalized_at` is anchored to on-chain reveal-block timestamp, not a client-
 * supplied `deliveredAt` field — partners have the same adversarial relationship
 * to a forged `deliveredAt` as to the rest of the bundle.
 */
const CLOCK_SKEW_TOLERANCE_SECONDS = 60;

/**
 * Default freshness window when the caller doesn't set `maxArtifactAgeSeconds`.
 * 24 hours (86_400 seconds) — matches typical webhook TTL norms, accommodates
 * partner SDKs that poll or batch-deliver within a daily cycle, and refuses
 * replay attempts after a day. Callers needing tighter or looser windows set
 * `maxArtifactAgeSeconds` explicitly; callers needing to disable the check
 * entirely set `disableFreshnessCheck: true`.
 */
export const DEFAULT_FRESHNESS_MAX_AGE_SECONDS = 86_400;

export function checkFreshness(bundle: RevealArtifactBundle, context: CheckContext): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);

  // Explicit opt-OUT is the ONLY path that returns `skipped`. Caller MUST
  // have SET the flag (not just omitted) — `disableFreshnessCheck` is a
  // type-discriminated boolean, audit-greppable. Same pattern as F-08
  // canonicalAddressPin's no-opt-in-via-undefined rule.
  if (context.options.disableFreshnessCheck === true) {
    return skippedCheck("FRESHNESS.SKIPPED_EXPLICIT_OPT_OUT", refs);
  }

  // Default-on: undefined `maxArtifactAgeSeconds` ⇒ apply the 24h default.
  // The caller no longer has an "I forgot the option" silent-skip path.
  const maxAge = context.options.maxArtifactAgeSeconds ?? DEFAULT_FRESHNESS_MAX_AGE_SECONDS;

  if (!Number.isFinite(maxAge) || maxAge <= 0) {
    return failCheck(
      "FRESHNESS.INVALID_OPTION",
      `maxArtifactAgeSeconds must be a positive finite number; got ${maxAge}`,
      refs,
    );
  }

  const finalizedRaw = bundle.authorization.finalized_at;
  if (typeof finalizedRaw !== "string" || finalizedRaw.length === 0) {
    return failCheck(
      "FRESHNESS.FINALIZED_AT_MISSING",
      "bundle.authorization.finalized_at is missing or empty",
      refs,
    );
  }
  const finalizedMs = Date.parse(finalizedRaw);
  if (!Number.isFinite(finalizedMs)) {
    return failCheck(
      "FRESHNESS.FINALIZED_AT_MALFORMED",
      `bundle.authorization.finalized_at is not a valid ISO-8601 timestamp: ${finalizedRaw}`,
      refs,
    );
  }

  const ageSeconds = (context.now.getTime() - finalizedMs) / 1000;

  if (ageSeconds < -CLOCK_SKEW_TOLERANCE_SECONDS) {
    return failCheck(
      "FRESHNESS.FUTURE_TIMESTAMP",
      `bundle.authorization.finalized_at is in the future by more than ${CLOCK_SKEW_TOLERANCE_SECONDS}s (age=${Math.round(ageSeconds)}s) — clock skew or forged timestamp`,
      refs,
    );
  }

  if (ageSeconds > maxAge) {
    return failCheck(
      "FRESHNESS.STALE",
      `bundle age ${Math.round(ageSeconds)}s exceeds maxArtifactAgeSeconds=${maxAge}s — possible replay`,
      refs,
    );
  }

  return passCheck("FRESHNESS.PASS", refs);
}
