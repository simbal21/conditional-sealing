> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Audit reconcile @ HEAD e87c108 (2026-06-02) — SD cleartext heap residue + log sanitizer wiring

Read-only audit. Verdicts are grep/read-verified against actual code at HEAD (Rule 45), not old finding text.

---

## TS-API-F-07 — SD cleartext survives in heap after success-path return (SD-D1/D3 partially unmet)

**Status: PARTIAL** (severity MEDIUM)

### What the code does at HEAD

`v3-sd/src/sd-plan/execute.ts`:
- Success path returns the bundle at **lines 181-205**, including `cleartext` (line 201) whose items carry `value: record.canonical_value` (the partner-visible plaintext for CLEARTEXT-policy fields — this is the legitimate SD-D1/D3 deliverable, not a leak by itself).
- The `finally` block (**lines 213-222**) calls `finalizeSdExecution(...)` — and a `finally` runs even on the success `return`, so input-buffer state IS zeroized on success.

`v3-sd/src/sd-plan/finalizer.ts` (`finalizeSdExecution`, lines 18-27) zeroes ONLY:
- `plaintext` record values → null (line 19, `zeroizeRecord`)
- `normalized_payload` → null (line 20)
- `sd_master_salt` Uint8Array fill(0) (line 21)
- `field_salts[]` fill(0) (line 22)
- `encoded_values[].bytes` fill(0) (line 23) — note: only the optional `bytes?` buffer
- `commit_store.zeroizeSalts()` (line 24) — `commit-store.ts:36-38` zeroes ONLY `salt_bytes`

### The residue that survives (verified)

1. `CommitStore` records (`commit-store.ts:7-19`) retain `canonical_value` (line 15) and `encoded` (line 14, an `EncodedFieldValue` whose `normalized_value` echoes the plaintext — `field-encoding.ts:39, 167, 174, 181, 185, 189, 194`). `zeroizeSalts()` does NOT touch these. grep confirms NO `canonical_value` / `normalized_value` zeroization anywhere (`grep canonical_value/normalized_value` in finalizer/commit-store → only the type decl at commit-store.ts:15).
2. The returned `bundle.cleartext[].value` (zk-opened.ts:40 / tee-attested.ts:31 set `value: record.canonical_value`) lives in caller heap until GC.
3. JS strings are immutable — string plaintext cannot be hard-zeroed in place.

### Why PARTIAL (not OPEN, not FIXED)

The codebase has explicitly responded to the May-14 finding since then:
- `v3-sd/src/cleartext-opening/zeroize.ts` is NEW and its header comment (lines 7-11, 36) names `Security-audit-2026-05-14 TS-API-F-07` directly. It exposes `zeroizeSdCleartext()` / `zeroizeSdBundleCleartext()` as an explicit best-effort heap-scrub helper.
- BUT this helper is **caller-side opt-in** — `executeSdAtCommit` never calls it; nothing in `src/` invokes it except the test (`tests/cleartext-opening/zeroize.test.ts`). grep for `zeroizeSdCleartext` callers in non-test src → none.
- The helper's own comment (zeroize.ts:21-24) concedes JS gives no eviction guarantee and that true closure needs a memory-isolated env (TEE/WASM/separate process).

So: input-buffer state is zeroized on success (improvement over the original finding's implication), an opt-in cleartext scrubber now exists, but the architectural residue the finding named — returned cleartext + immutable-string plaintext + un-zeroed `canonical_value`/`normalized_value` in commitStore — still lives in heap post-return. The finding is **mitigated, not closed**. Matches the code's own "partial SD-D1/D3 compliance gap" self-assessment.

### fix_location (to move PARTIAL → FIXED, if pursued)
- `v3-sd/src/sd-plan/finalizer.ts`: extend `finalizeSdExecution` / `commit-store.ts zeroizeSalts` to also null out `canonical_value` and `encoded.normalized_value` on every record (replace-with-null for immutable values; fill(0) any `encoded.bytes`).
- `executeSdAtCommit` would need to call `zeroizeSdBundleCleartext` only AFTER the partner SDK has consumed the returned bundle — which it structurally cannot do inside this function (it returns the bundle to the caller). True closure is architectural: run post-onboarding cleartext consumption inside a TEE/WASM sandbox (zeroize.ts:22-24). This is the part that makes the residual ARCHITECTURAL by nature; the in-function part (canonical_value/normalized_value zeroization) is the buildable delta.

---

## TS-API-F-09 — log sanitizer implemented but not wired into Pino

**Status: OPEN** (severity LOW)

### Verified at HEAD

`v3-api/src/redaction/log-sanitize.ts`:
- `sanitize()` (lines 29-82) and `pinoLogFormatter()` (lines 91-93) are fully implemented.
- File header (lines 2-4) AND the `pinoLogFormatter` JSDoc (lines 85-90) BOTH still say the Pino/Fastify integration is "Phase D" / future — the formatter shows a `pino({ formatters: { log: ... } })` snippet as a TODO example, not as live wiring.

### Wiring search (grep-verified — NOT wired)

- `pinoLogFormatter` consumers in the packages (excluding its own file and the redaction barrel): **only the foundation test** `v3-api/tests/foundation/redaction-pii-absent.test.ts:8,97`. No production consumer.
- `sanitize(` callers: only that same test file (lines 56, 62, 75). No production caller.
- `v3-api/src/index.ts:23` merely re-exports `./redaction/index.js`; `redaction/index.ts:2` re-exports `log-sanitize.js`. Re-export ≠ wiring.
- Server factory `v3-api/src/server/index.ts:90`: `const app = Fastify(deps.fastifyOptions ?? { logger: false });` — **logger is OFF by default**, and `pinoLogFormatter` is never passed in `fastifyOptions` anywhere.
- No `setErrorHandler` / `onSend` / `serializerCompiler` / `setReplySerializer` in `v3-api/src` (grep → zero hits). Error bodies — explicitly named in the §10.2 redaction-target list quoted at log-sanitize.ts:6-10 — are therefore NOT routed through `sanitize`. `src/errors/problem.ts` builds problem-detail bodies with no sanitize pass.
- `pino`/`pino-pretty` are declared deps (`package.json:67-68`) but never imported in `src` (only the doc-comment `pino({` at log-sanitize.ts:87).

### Why OPEN (not MOVED-TO-BUILD)

The sanitizer exists and is unit-tested, but the protective effect (PII/σ/DEK/salt redaction at log + error-body egress) is **inert** — nothing in the request path consumes it, and the default logger is off. The finding as stated ("implemented but not wired into Pino") is exactly true at HEAD. The code labels this as deferred Phase-D integration work, so it is genuinely outstanding build work rather than an accepted architectural posture; flagging OPEN (the build is real and not yet done). If the team treats Phase-D wiring as a tracked build item, MOVED-TO-BUILD is defensible, but at HEAD the gap is live.

### fix_location
- `v3-api/src/server/index.ts:90`: replace `{ logger: false }` default with a Pino logger configured `formatters: { log: pinoLogFormatter }` (import from `../redaction/log-sanitize.js`).
- Add `app.setErrorHandler(...)` in the same factory that runs the problem-detail body through `sanitize()` before reply, since error bodies are a named §10.2 redaction target and bypass the log formatter.
