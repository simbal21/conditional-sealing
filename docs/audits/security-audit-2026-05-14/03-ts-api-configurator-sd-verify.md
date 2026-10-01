> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# TypeScript Audit Report — Outer Ring (v3-api · v3-configurator · v3-sd · verify-sdk)

**Audit date:** 2026-05-14  
**Auditor:** typescript-architect agent (Sonnet 4.6)  
**Packages audited:** v3-api, v3-configurator, v3-sd, verify-sdk  
**Lens focus:** Input validation at untrusted boundaries, PDA validation completeness, SD asymmetric isolation, verify-sdk correctness, shred atomicity

---

## Files audited (primary reads)

- `/v3-api/src/ingest/routes-create-mode-a.ts`
- `/v3-api/src/ingest/routes-get-status.ts`
- `/v3-api/src/partner/routes-create-shred-request.ts`
- `/v3-api/src/subject/routes-create-shred-request.ts`
- `/v3-api/src/verify/routes-verify-artifact-bundle.ts`
- `/v3-api/src/redaction/log-sanitize.ts`
- `/v3-configurator/src/pda/emit.ts` (core: `validatePDA`, `prepareSubmittedPda`)
- `/v3-configurator/src/pda/verify.ts`
- `/v3-configurator/src/validate/stage3/index.ts`
- `/v3-configurator/src/validate/syntax/required-fields.ts`
- `/v3-configurator/src/cli/validate.ts`
- `/v3-sd/src/sd-plan/execute.ts`
- `/v3-sd/src/sd-plan/finalizer.ts`
- `/v3-sd/src/commit/salt-derivation.ts`
- `/v3-sd/src/boundary/boundary.ts`
- `/verify-sdk/src/verify-artifact-bundle.ts`
- `/verify-sdk/src/verify-webhook.ts`
- `/verify-sdk/src/checks/chain-proof.ts`
- `/verify-sdk/src/checks/sigma-lit.ts`
- `/verify-sdk/src/checks/sigma-g4.ts`
- `/verify-sdk/src/checks/provenance.ts`
- `/verify-sdk/src/checks/canonicalization.ts`
- `/verify-sdk/src/types.ts`

---

## Summary

- Total checks run: 23
- PASS: 14 | FAIL: 9 | N/A: 0
- CRITICAL: 0 | HIGH: 3 | MEDIUM: 4 | LOW: 2

---

## Findings

---

### F-01 [HIGH] — Ingestion request schema uses `additionalProperties: true`

**File:** `v3-api/src/ingest/routes-create-mode-a.ts:163`  
**Lens:** 1 (Input validation at untrusted boundary)

**Issue:** `ModeAIngestionRequestSchema` — the TypeBox schema governing the primary ingestion POST `/v1/ingestions` — is declared with `additionalProperties: true` (line 163). This allows arbitrary unknown fields to enter the ingestion handler alongside the validated fields. At line 155, `plaintext_payload` is typed as `Type.Unknown()`, meaning any JSON value is accepted without type, length, or structural validation before it is serialized to bytes (line 443 via `bytesFromPayload`) and written to the vault.

The response schema at line 191 also uses `additionalProperties: true`, which is lower risk (output) but contributes to a general permissive posture.

**Why it matters:** An attacker with partner HMAC credentials can inject an unboundedly large `plaintext_payload` (no max-length check before vault write), unknown extra fields that could interfere with downstream JSON processing, or confusingly shaped objects that break idempotency key derivation. The `payload_classification` field (line 154) accepts an unbounded open record; a malicious partner could set classification keys that influence downstream audit/logging paths without validation.

**Fix hint:** Change line 163 to `{ additionalProperties: false }`. Add a `Type.Unknown()` → `maxByteLength` guard in the handler before `bytesFromPayload`. For `plaintext_payload`, enforce a maximum serialized byte length (e.g., 1 MB) before passing to vault. Validate `payload_classification` against an enum of permitted classification keys.

**Confidence:** HIGH

---

### F-02 [HIGH] — `h_commit` URL path parameter accepted without format validation in two shred routes

**File (partner):** `v3-api/src/partner/routes-create-shred-request.ts:50`  
**File (subject):** `v3-api/src/subject/routes-create-shred-request.ts:47`  
**Lens:** 1 (Input validation), 5 (Shred atomicity)

**Issue:** Both shred-request routes accept `:h_commit` as a path parameter via `request.params.h_commit` (partner line 50, subject line 47) and pass it directly to the lookup function — `getPartnerEscrow` / `getSubjectEscrowRecord` — without first validating that it matches the `^0x[0-9a-fA-F]{64}$` pattern. Compare the status GET route (`routes-get-status.ts:48`) which explicitly calls `isHex32(hCommit)` before any lookup. The shred routes do not perform this pre-check.

**Why it matters:** A malformed `h_commit` (e.g., an SQL-injection-shaped string, a 0-byte value, or a value that is longer than 66 chars) could cause unexpected behavior in the map lookup or, if the lookup is later replaced with a database query, create injection vectors. More concretely, a subject could craft a non-canonical `h_commit` that matches one entry in the in-memory store but would fail the Hex32 check — leading to authorization bypass if the store is later extended. The shred path is safety-critical; a mismatch here means either an incorrect shred request is created or an authorization check is bypassed.

**Fix hint:** Add an `isHex32(h_commit)` guard at the top of both `createPartnerShredRequest` and `createSubjectShredRequest`, throwing a 400 `REQUEST_MALFORMED` problem if the check fails — same pattern as `getIngestionStatus` at `routes-get-status.ts:48-52`.

**Confidence:** HIGH

---

### F-03 [HIGH] — verify-sdk `verifyArtifactBundle` has no artifact freshness / `finalized_at` check

**File:** `verify-sdk/src/verify-artifact-bundle.ts:24-60`  
**Lens:** 4 (Partner verify-sdk correctness — replay protection)

**Issue:** The `RevealArtifactBundle` type carries `authorization.finalized_at` (a required timestamp, `types.ts:161`) and `chain_proofs.finalized_at` (an optional timestamp, `types.ts:51`). Neither value is checked by any of the 15 named verification checks in `verifyArtifactBundle`. The SDK verifies the challenge window (`chain-proof.ts:45`) but only to confirm the window has elapsed, not to bound how old the artifact is. There is no maximum artifact age check anywhere in the codebase.

This means a partner can replay a valid artifact from years ago against `verifyArtifactBundle` and receive `overall: "pass"`. The signature checks (`sigmaLit`, `sigmaG3`, `sigmaG4`) verify structural format only — they do not verify the sigma values against any public key or confirm the sigma values correspond to a specific authorization block that is still final on-chain (offline verification path). In offline mode the only temporal anchor is `chain_proofs.challenge_window_expired_at` confirming the window closed, not how long ago it closed.

**Why it matters:** Legal-evidentiary bundles (§371a ZPO) must be temporally bound to the authorization event. A recipient running verify-sdk offline against a replayed bundle has no means of detecting the replay. For enforcement use cases, a partner could present an old, revoked authorization as currently valid.

**Fix hint:** Add a `checkFreshness` check as check #16 (or incorporate into `chainProof`). When `options.now` is set, compare `now` against `bundle.authorization.finalized_at`: if `now - finalized_at > options.maxArtifactAgeDays` (configurable, default e.g. 365 days) return `fail`. Also check `bundle.shred_state.shred_state` — if it is not `"not_shredded"` or `"unknown"`, the artifact should fail regardless of other checks. The `shredState` check already exists but currently only validates structural presence, not the value.

**Confidence:** HIGH

---

### F-04 [MEDIUM] — `ModeAIngestionRequestSchema` outer object is `additionalProperties: true` but `PreflightCommitContextSchema` nested schemas use `additionalProperties: false` inconsistently

**File:** `v3-api/src/ingest/routes-create-mode-a.ts:83-84,163`  
**Lens:** 1 (Input validation)

**Issue:** Sub-schemas for `AttestationPreflightSchema`, `RegistrySnapshotRefSchema`, and others use `additionalProperties: false` (lines 41-60, 83-139), correctly rejecting unknown nested fields. However the root `ModeAIngestionRequestSchema` object uses `additionalProperties: true` (line 163). This means unknown top-level keys (e.g., `debug_bypass`, `__proto__`) are admitted and propagated through to the response schema (`ModeAIngestionResponseSchema`, also `additionalProperties: true` at line 191) and into idempotency-key digest computation at `recordDigest` (line 392-403). Since `recordDigest` only hashes a fixed set of fields rather than the full body, additional top-level fields are silently ignored — but they are still present in the parsed body that reaches the vault writer.

**Fix hint:** Change root `ModeAIngestionRequestSchema` to `additionalProperties: false`. If forward-compatibility is needed for new optional fields, enumerate them explicitly in the schema or use a versioned extension mechanism.

**Confidence:** MEDIUM

---

### F-05 [MEDIUM] — Stage 3 and Stage 4 validation context uses synthetic placeholder values rather than submitted PDA data

**File:** `v3-configurator/src/pda/emit.ts:280-320`  
**Lens:** 2 (PDA validation completeness — S2-4 §5)

**Issue:** `buildStage3Context` (line 280) constructs the `allowLists`, `bounds`, and `registryEntries` maps entirely from the CLASS_TABLE rows using synthetic patterns: allow-lists are set to `[allowed:${row.id}]` and bounds to `{ min: 0, max: 10 }` regardless of the submitted PDA's actual field values. Similarly, `adaptToStage3` (line 309) generates surface values synthetically: `(b) PDA pick` rows receive value `allowed:${row.id}` (always in the allow-list by construction), and `(c) PDA parameter` rows receive value `5` (always within `[0,10]`).

The result is that Stage 3 validation passes deterministically for every submitted PDA, because both the values under test and the allow-list / bounds come from the same synthetic source and are designed to match. The actual submitted field values from the partner are never tested against real production allow-lists or production bounds at Stage 3.

**Why it matters:** S2-4 §5 Stage 3 is the PDA+/PDA allow-list and bounds enforcement gate — the layer that prevents, for example, a partner from setting `retention_seconds` to `0` (bypassing retention), `shred_authority` to an unapproved value, or referencing an oracle not in the approved list. Because Stage 3 runs on synthetic inputs, a partner-submitted PDA that violates these constraints will pass Stage 3 validation and be emitted as a valid artifact.

**Fix hint:** `buildStage3Context` should populate `allowLists` and `bounds` from a production policy store (or a hardcoded Cealis-internal policy table), not from the class table row IDs. `adaptToStage3` should extract actual field values from the `submitted` PDA and map them to `Stage3SubmittedSurface.value`, not use round-trip synthetic values. The `registryEntries` map should either be provided by a real registry probe or explicitly documented as `offline_check_skipped` with a `status` field.

**Confidence:** HIGH (the code is unambiguous — `adaptToStage3` generates values that match the synthetic allow-list by construction)

---

### F-06 [MEDIUM] — `verifyArtifactBundleServerSide` (v3-api route) performs structural key presence check only — no crypto verification

**File:** `v3-api/src/verify/routes-verify-artifact-bundle.ts:17-36`  
**Lens:** 4 (Partner verify-sdk correctness)

**Issue:** The server-side `/v1/verify/artifact-bundles` endpoint (`verifyArtifactBundleServerSide`, line 17) only checks that the submitted bundle's top-level keys are all present (i.e., none are `undefined`). All 15 named checks receive the same status (`"pass"` or `"fail"` based solely on key presence), with code `STRUCTURAL_CHECK_PRESENT`. No cryptographic verification is performed. The `sdk_replacement: false` flag at line 31 acknowledges this is a scaffold, not a replacement for the SDK.

The problem is that partners calling `POST /v1/verify/artifact-bundles` receive a response containing `overall: "pass"` and all 15 check names as `"pass"` whenever the bundle has the required keys — even if the artifact bundle digest is wrong, the sigma values are zeroed, the challenge window has not expired, or the chain proof is fabricated.

**Why it matters:** A partner who uses the server-side endpoint instead of the SDK client library gets a falsely authoritative `"pass"` across all check dimensions with no crypto validation. If `sdk_replacement` is expected to remain `false` forever (scaffolding), the route should either: (a) return 501 Not Implemented with a clear message directing partners to the SDK, or (b) be gated behind an internal-only auth scope so it is never called by external partners in production.

**Fix hint:** Either return HTTP 501 with `{ error: "USE_CLIENT_SDK", message: "Server-side structural cross-check is not a cryptographic verifier. Use @cealis/verify-sdk client-side." }`, or call `verifyArtifactBundle` from `@cealis/verify-sdk` directly and return its result. If the scaffolding must remain, add a prominent `X-Cealis-Verify-Stub: true` response header and document that the endpoint is internal-only.

**Confidence:** MEDIUM

---

### F-07 [MEDIUM] — `executeSdAtCommit`: success branch early return exits the `try` block without reaching `finally` zeroing for the success-path salt buffers

**File:** `v3-sd/src/sd-plan/execute.ts:181-205`  
**Lens:** 3 (SD asymmetric isolation — SD-D5 salt never leaves TEE)

**Issue:** The success path of `executeSdAtCommit` (line 181) executes `return { status, sdMerkleRootBytes: rootBytes, bundle: { ... } }` from inside the `try` block (lines 181-205). In JavaScript/TypeScript, a `return` inside a `try` block does trigger the `finally` block — so `finalizeSdExecution` at line 214 IS called. However, the `return` statement is inside a deeply nested `if` block (line 83: `if (!skip_generation && sd_master_salt && normalized_payload)`), which means that if the success branch is taken, the `sd_master_salt` local variable will have been assigned and the `field_salts` array will be populated. These are correctly zeroed by `finalizeSdExecution`.

Upon inspection this is actually **correct** — `finally` fires on all exit paths including `return` in JS. However, there is a subtle issue: the `sd_master_salt` variable at line 64 is typed as `Uint8Array | null`. The `zeroizeUint8` call in `finalizer.ts:21` calls `.fill(0)` but the actual buffer that was returned by `deriveSdMasterSalt` (line 80) is the original allocation. If `hkdf` returns a new allocation each time, the reference in `sd_master_salt` points to the right buffer. This is correct as implemented.

The actual MEDIUM finding is different: on the success path, `cleartext` items built at line 143-161 include `buildZkOpenedCleartextItem` which embeds `sdMerkleRoot` and merkle proof nodes — these are included in the returned `bundle.cleartext` array (line 201). The `finalizeSdExecution` does NOT zero the `cleartext` array items. If the calling code holds the bundle in memory and the TEE boundary is the JavaScript process boundary (which it is for Phase 1 PoF), the cleartext field values are retained in the bundle object after `finalizeSdExecution` returns. This is expected for delivery, but the issue is that the `sd_master_salt` is zeroed while its *derived outputs* (the encoded field values and the cleartext items) are retained in the caller's bundle object — creating a situation where partial cleartext field values survive in memory even if the TEE wants to "destroy them after processing" (SD-D1/D3).

**Why it matters:** SD-D1/D3 requires that after TEE processing, plaintext data is destroyed. The `finalizeSdExecution` zeroes the raw buffers (salt, encoded bytes), but the structured `cleartext` array that is part of the returned bundle contains decoded field values embedded in the `SdCleartextItem` objects. These survive in the caller's memory as long as the bundle is held. For Phase 1 (process boundary TEE stub), this is inherent, but the boundary document (`src/boundary/boundary.ts`) does not call `finalizeSdExecution` or any zeroing — the caller is responsible for not holding the bundle longer than necessary.

**Fix hint:** Document explicitly in `boundary.ts` that the `bundle` returned from `executeIfEscrowOk` must not be retained in memory beyond the HTTP response flush. Add a `zeroizeBundle(bundle)` helper that overwrites `bundle.cleartext[*].canonical_value` and `bundle.cleartext[*].encoded_bytes` references to null after serialization. Mark Phase 1 TEE stub as needing upgrade at this boundary in production.

**Confidence:** MEDIUM

---

### F-08 [LOW] — `prepareSubmittedPda` coerces missing partner-supplied fields to non-failing defaults, suppressing Stage 1 required-field failures

**File:** `v3-configurator/src/pda/emit.ts:192-278`  
**Lens:** 2 (PDA validation completeness)

**Issue:** `prepareSubmittedPda` (line 192) accepts a raw `Record<string, unknown>` from untrusted partner input and synthesizes a `SubmittedPda` by filling in defaults for all optional and many required fields. For example: `partner_id` defaults to `"partner_fixture"` (line 213), `pda_version` defaults to `1` (line 212), `template_id` is generated from a hash seed if missing (line 200), `pda_id` is generated if missing (line 201), and `retention_seconds` defaults to `31_536_000` (line 269). The `REQUIRED_FIELDS` array in `validate/syntax/required-fields.ts:17-29` includes `pda_id`, `pda_version`, `partner_id`, `template_id`, and others — but because `prepareSubmittedPda` fills these with defaults BEFORE `runStage1` is called (line 158 of `validatePDA`), Stage 1 always receives a fully-populated struct and never fires `MISSING_REQUIRED_FIELD` for these fields.

This means a partner could submit a PDA with no `partner_id`, no `pda_id`, and no `template_id`, receive a valid Stage 1 pass, and get an emitted artifact with synthetically assigned identifiers that do not reflect their intent.

**Why it matters:** PDA artifacts are content-addressed (via `pdaRoot`) and submitted to the on-chain registry. If a partner submits a PDA with missing fields and receives a synthetic `partner_id` of `"partner_fixture"`, the on-chain registration will use the wrong partner identity. This is a data-integrity issue rather than a security breach, but it could lead to authorization misattribution if artifacts generated this way are later used in enforcement.

**Fix hint:** In `validateFile` and any API endpoint that calls `validatePDA` or `emitPDA`, run `checkRequiredFields` on the RAW input before calling `prepareSubmittedPda`, and reject submissions where required fields are absent. Alternatively, split `prepareSubmittedPda` into two phases: a strict mode (for partner submissions) and a permissive mode (for internal scaffold generation).

**Confidence:** MEDIUM

---

### F-09 [LOW] — `pinoLogFormatter` and `sanitize` are defined but their wiring into Pino/Fastify is Phase D deferred — currently no log sanitization is active

**File:** `v3-api/src/redaction/log-sanitize.ts:91-93`  
**Lens:** 1 (Input validation / PII leakage boundary)

**Issue:** The `pinoLogFormatter` function (line 91) and the `sanitize` function (line 29) are correctly implemented — they would redact sigma, DEK, salt, share, and plaintext values from log output. However, the inline comment at line 88 (`Phase D wires`) and the Phase A stub note in the file header make clear that these functions are NOT yet wired into the actual Pino logger or Fastify error handler. The functions exist but are not called in any production code path at this stage.

Until Phase D wiring occurs, any `logger.error(body)` or `logger.debug(someObject)` call that accidentally includes a key that passes through the raw body (e.g., error handlers that serialize the raw Fastify request body, which includes `plaintext_payload`) would log PII without redaction.

**Why it matters:** LOW for now because it is an acknowledged PoF/Phase 1 gap rather than an active leak. However it becomes CRITICAL if Phase D is delayed and the service is exposed in any semi-production context. A future audit should verify that `pinoLogFormatter` is wired before any deployment that handles real personal data.

**Fix hint:** Add a CI/lint rule that prevents any direct `pino()` logger creation without `formatters: { log: pinoLogFormatter }`. Until Phase D is complete, at minimum ensure that Fastify's `logger` config in `src/index.ts` uses the sanitizing formatter, even at the cost of some performance.

**Confidence:** HIGH (the code is clear that wiring is deferred)

---

## PASS findings

| # | Check | Notes |
|---|-------|-------|
| P-01 | SD asymmetric isolation — `SdBoundary.executeIfEscrowOk` | `boundary.ts:11-12` correctly returns `sd_skipped` when escrow result is `err`, preventing SD errors from propagating upward to block escrow. SD-D9 NORMATIVE satisfied. |
| P-02 | SD error handling — `executeSdAtCommit` catch block | Lines 207-222 catch all exceptions in the SD path and return `status: "failed"` with a non-throwing result. Escrow pipeline never sees SD exceptions. |
| P-03 | Salt zeroing — `finalizeSdExecution` | `finalizer.ts:18-27` correctly zeros `sd_master_salt`, all `field_salts`, `encoded_values[*].bytes`, and calls `commit_store.zeroizeSalts()`. SD-D5 salt lifecycle is implemented for the successful and failed paths. |
| P-04 | Salt never returned outside TEE — salt derivation module | `salt-derivation.ts` exports only derived `scalar` and `salt_bytes` via `DeriveSdFieldSaltResult`. The raw HKDF output is never placed in the `bundle` object directly. |
| P-05 | PDA validation stage sequencing — `validatePDA` | `emit.ts:156-190`: stages are correctly gated: Stage 2 only runs if Stage 1 passes, Stage 3 only if Stage 1+2 pass, Stage 4 only if Stage 1+2+3 pass. Short-circuit correctly prevents later stages from masking earlier failures. `throwIfInvalid` enforces the same gate sequence for `emitPDA`. |
| P-06 | Cross-field validation completeness | `validate/cross-field/` directory contains cf-01 through cf-07, all dispatched by `validateCrossFieldRules`. All 7 are reachable as Stage 4. |
| P-07 | Mode B rejection at ingestion boundary | `routes-create-mode-a.ts:363-376`: `assertModeAOnly` correctly detects Mode B requests by checking `mode`/`ingestion_mode` strings and throws a problem before any processing begins. |
| P-08 | Attestation preflight digest binding | Lines 446-455: `assertPreflightDigestMatches` recomputes the JCS digest of `preflight_commit_context` server-side and compares to the client-supplied `preflight_context_digest`. Man-in-the-middle modifications to the commit context are caught. |
| P-09 | Payload digest verification | Lines 433-444: `assertPayloadDigestMatches` recomputes the payload digest server-side before vault write. Payload tampering between client and server is caught. |
| P-10 | Idempotency key collision detection | Lines 486-495: `getByIdempotencyKey` checks `request_digest` equality on replay; a different body under the same key throws `IDEMPOTENCY_KEY_CONFLICT`. |
| P-11 | Challenge window temporal check in verify-sdk | `chain-proof.ts:45`: `Date.parse(bundle.authorization.challenge_window_expired_at) > context.now.getTime()` enforces the challenge window has elapsed before passing chain proof. |
| P-12 | Webhook replay window in verify-sdk | `verify-webhook.ts:9,81-94`: 300-second replay window enforced via `checkReplayWindow`. Timing-safe HMAC comparison at line 68. |
| P-13 | Sigma evidence structural validation | `sigma-lit.ts` `checkSigmaEvidence` checks non-empty hex sigma, 32-byte authority_ref, `public_after_reveal: true`. Applied uniformly to sigma_lit, sigma_g3, sigma_g4. |
| P-14 | Log sanitizer PII key patterns | `log-sanitize.ts:62-75`: key names `sigma`, `dek`, `file_key`, `share`, `plaintext`, `decap`, `salt`, `witness` are redacted by key name heuristic. Catches accidental logging even when values don't match patterns. |

---

## Cross-cutting concerns

### CC-1: Stage 3 validation is currently a no-op against real partner data

The most structurally significant issue is F-05: Stage 3 validation in the configurator is designed to enforce production allow-lists and bounds, but the implementation tests synthetic values against synthetic allow-lists derived from the same class table. Any partner PDA — regardless of its actual field values — will pass Stage 3 as currently implemented. This is not a scaffolding note in the code; it is presented as a functioning validator. If this were deployed as-is and a partner-submitted PDA with a disallowed oracle reference or out-of-bounds retention window reached the on-chain registry, the Stage 3 gate would have provided no protection.

This finding interacts with F-08: because `prepareSubmittedPda` fills missing fields with defaults before Stage 1 runs, and Stage 3 is a no-op, the effective validation gate for partner-submitted PDAs in the current implementation is: Stage 1 (required fields — but bypassed by defaults) and Stage 2 (crypto invariants). Stages 3, 4, and 5 provide weaker guarantees than their names suggest.

### CC-2: Shred path is a status-registration stub, not an atomic shred

Both shred routes (F-02) set `vault_deletion_status: "pending_on_chain_confirmation"` and store the shred request in an in-memory map (`context.store.shreds.set`). There is no actual vault deletion, no DEK destruction, no G1/G4 gate revocation, and no gate-recipient pubkey invalidation in these handlers. This is consistent with the V3 architecture where shred completion is driven by on-chain events (the shred-listener in `v3-sd/src/onchain/shred-listener.ts`), but the shred routes themselves do not validate that `blocked_future_reveal` will actually be enforced or that the in-memory store persists across restarts. In production, if the service restarts between the partner's shred request and on-chain confirmation, the pending shred record is lost. Recommend persisting shred requests to the database immediately and confirming via on-chain event before returning 202.

### CC-3: verify-sdk sigma checks are structural only — no cryptographic verification of sigma values

`checkSigmaLit`, `checkSigmaG3`, `checkSigmaG4` verify that the `sigma` field is non-empty hex and that `authority_ref` is 32-byte hex. They do not verify the sigma value cryptographically against the authority public key. This is documented as "structural" checking, but partners running offline verification receive `sigmaLit: pass` / `sigmaG3: pass` / `sigmaG4: pass` without any cryptographic assurance that the sigma values are valid attestations from the registered gate operators. Partners must be clearly warned (in SDK documentation and the `VerifyArtifactOptions` type) that offline verification is structural only and that `requireOnlineRegistryChecks: true` must be set for enforcement-grade verification.

---

## CRITICAL and HIGH quick-scan

| Severity | Finding | File |
|----------|---------|------|
| HIGH | F-01: Ingestion request schema `additionalProperties: true` — unbounded payload accepted | `v3-api/src/ingest/routes-create-mode-a.ts:163` |
| HIGH | F-02: `h_commit` URL param not format-validated in shred routes | `v3-api/src/partner/routes-create-shred-request.ts:50`, `v3-api/src/subject/routes-create-shred-request.ts:47` |
| HIGH | F-03: verify-sdk has no artifact freshness / `finalized_at` check — replay of old valid artifacts passes | `verify-sdk/src/verify-artifact-bundle.ts:24-60` |
| HIGH | F-05: Stage 3 PDA validation is a no-op — synthetic values test against synthetic allow-lists | `v3-configurator/src/pda/emit.ts:280-320` |
