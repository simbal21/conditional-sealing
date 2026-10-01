> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Audit reconciliation — verify-sdk freshness + server-side artifact verify

HEAD: e87c108 (2026-06-02). Read-only audit. Rule 45 discipline: verdict is HEAD code via grep/read.

## TS-API-F-03 (HIGH) — verifyArtifactBundle freshness / replay defense → FIXED

**Original finding:** `verifyArtifactBundle` had NO freshness check, so a captured legitimate
bundle could be replayed back to a partner months later and pass all structural checks.

**HEAD state — FIXED, default-on enforced:**

- `verify-artifact-bundle.ts:23` imports `checkFreshness`; `:50` wires `freshness: checkFreshness(bundle, context)` into the aggregated `checks` object. `context` (`:31`) carries `{ options, now }` where `now = options.now ?? new Date()` (`:29`).
- `overallStatus` (`verify-artifact-bundle.ts:66-70`): any `status === "fail"` ⇒ overall `fail`. A stale bundle's `FRESHNESS.STALE` fail therefore fails the whole bundle. Not bypassable via aggregation.
- `checks/freshness.ts` is genuinely DEFAULT-ON:
  - `:48-50` — the ONLY `skipped` return requires `context.options.disableFreshnessCheck === true` (strict `=== true`).
  - `:54` — `const maxAge = context.options.maxArtifactAgeSeconds ?? DEFAULT_FRESHNESS_MAX_AGE_SECONDS;` → omitting the option applies the **86_400s (24h)** default (`:39`), it does NOT skip.
  - `:91-97` — `ageSeconds > maxAge` ⇒ `failCheck("FRESHNESS.STALE", ...)`. Replay after the window FAILS.
  - `:83-89` — future-timestamp guard (60s clock-skew tolerance, `:29`) ⇒ `FRESHNESS.FUTURE_TIMESTAMP` fail.
  - `:64-79` — missing/malformed `finalized_at` ⇒ FAIL (not skip). `finalized_at` anchored to on-chain reveal-block timestamp per the doc comment (`:25-27`), not a client-supplied `deliveredAt`.
- `disableFreshnessCheck` is type-discriminated boolean (`types.ts:241`), audit-greppable; `=== false` explicitly does NOT skip (test below).

**Test coverage (`tests/all-15-checks.test.ts`):**
- `:21` "ENFORCES 24h default when maxArtifactAgeSeconds is not set ... opt-in DELETED" → `freshness.status === "pass"` / `FRESHNESS.PASS`.
- `:35` "ENFORCES 24h default — stale bundle (>24h) FAILS when option omitted" → `status === "fail"` / `FRESHNESS.STALE`.
- `:52` "SKIPS only when disableFreshnessCheck === true".
- `:65` "NOT skipped when disableFreshnessCheck === false (explicit-false ≠ opt-out)" → pass (enforced).
- `:79` "disableFreshnessCheck === true skips even on a stale bundle".
- `:93,104,113,122,131` — STALE / invalid-option (0/neg/NaN) / missing finalized_at all FAIL.

**Residual (cosmetic, NOT a finding):** stale comments at `verify-artifact-bundle.ts:48-49`
("Returns `skipped` unless caller sets maxArtifactAgeSeconds") and `types.ts:337-339`
("Defaults to `skipped` unless caller sets maxArtifactAgeSeconds; partner SDKs should opt in")
describe the OLD pre-R2b-3 opt-in behavior. The CODE is default-on (freshness.ts:54 + tests).
Comment-drift only — no security impact. Worth a one-line comment fix on next touch.

**Verdict: FIXED.**

## TS-API-F-06 — verifyArtifactBundleServerSide fake "pass" on key-presence → FIXED

**Original finding:** server-side endpoint returned `overall: "pass"` on top-level key-presence
only, no crypto verification; a partner trusting it would accept forged bundles.

**HEAD state — FIXED, fail-closed + explicit acknowledgement gate:**

- `routes-verify-artifact-bundle.ts:51-72` — no-opt-in path: if `acknowledge_structural_only !== true`,
  returns `overall: "fail"`, every named check `status: "fail"` / `code: "STRUCTURAL_ONLY_NOT_ACKNOWLEDGED"`,
  `sdk_replacement: false`, and an embedded `warning` string. Fails closed.
- `:74-94` — opt-in path (only reachable when partner explicitly set `acknowledge_structural_only: true`):
  `overall = missing.length === 0 ? "pass" : "fail"`, still `sdk_replacement: false`, still embeds a
  warning ("This is NOT a cryptographic verification — use @cealis/verify-sdk locally").
- The endpoint is explicitly retained for structural-only debugging; the comment block (`:31-49`)
  documents that enforcement-grade verification MUST use the local `@cealis/verify-sdk` (16-check
  pipeline incl. freshness, chain-proof receipt, per-stanza σ recovery). Server is not in the trust path.
- Route wired at `:97-103` (`POST /v1/verify/artifact-bundles`), registered via `index.ts:13`.

**Nuance:** even in the opt-in path, a "pass" is a structural-only pass labeled `sdk_replacement: false`
with a warning — it is NOT a crypto pass and is gated behind explicit partner acknowledgement that it
is structural-only. This is the documented, accepted design (server cannot do enforcement-grade verify
because it sits in the trust path). The fake-pass-by-default defect is removed.

**Verdict: FIXED.**
