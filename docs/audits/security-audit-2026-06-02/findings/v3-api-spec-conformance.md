> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# v3-api ↔ S2-5 ingestion-delivery-api-spec.md — spec-to-code conformance audit

Audit date: 2026-06-02 · HEAD e87c108 · Read-only.
Spec: `docs/specs/ingestion-delivery-api-spec.md` (S2-5, 2743 lines).
Pkg: `v3-api/`.
Method: grep/read against ACTUAL CODE AT HEAD (Rule 45). Ran the suite: 223 pass / 15 skipped (postgres-store tests need live DB).

## Verdict: MINOR-DEVIATIONS

The HTTP-contract, crypto-detail, and security-discipline layers conform tightly and are well-tested. The deviations are: (1) the production server factory does NOT mount most of the 29 canonical endpoints (documented scaffold boundary — R2b worker-2 territory), (2) the unused `OPERATION_TO_PATH` metadata table has 4 stale paths that disagree with the actual handlers and canonical.yaml (latent foot-gun, not a served-route bug), and (3) several deep verification steps (on-chain DCAP/registry verification, SD pipeline, mTLS cert validation, raw-body capture) are stubbed/deferred. None of these are correctness defects in the route logic that IS present.

## What CONFORMS (high confidence, verified at HEAD)

- **HMAC schemes byte-exact.** Partner canonical_request (§1.2: METHOD\nPATH\nTS\nNONCE\nsha256(body-hex)) and webhook preimage (§7.2: `utf8(ts) "." rawBody`, 0x2E dot byte) are exactly right — `src/auth/canonical-request.ts`. Constant-time compare both schemes.
- **Partner HMAC middleware** (`src/auth/hmac-middleware.ts`): 300s replay window, nonce-no-repeat-24h via nonceStore, revoked-credential rejection, scope enforcement (§5.1 8 scopes via `src/auth/scope-enforce.ts` + `types/scopes.ts`).
- **Mode A ingestion** (`src/ingest/routes-create-mode-a.ts`): Mode B rejection → `409 SCHEMA.MODE_B_RESERVED` (§2.1); server RE-computes preflight_context_digest, payload_digest, and all PDA fields (equality-checked, not trusted — §2.5); four-check attestation verify (`src/g4/preflight-recompute.ts` maps to §2.8 codes); idempotency conflict on divergent digest (§1.5); VAULT.UNAVAILABLE retryable (§2.8); `commit_version` hardcoded `0x0302` (§1.1); Phase 1 trust statement (§2.3); `additionalProperties:false` hardening (closes prior TS-API-F-01/04).
- **G4 phase policy** (`enforceG4PhasePolicy`): Phase 1 rejected for partner-ready/legal-effect commits (§11.3 / S2-4 CF-05); only consumer non-partner-ready dev-scaffold may use Phase 1.
- **Universal tripwire / §3.1 reveal preconditions** — the strongest part. `src/reveal/reveal-coordinator-impl.ts` enforces all 5 preconditions (RevealAuthorized present+confirmed, challenge closed, shred-not-blocking incl. `NOT post_challenge_reveal_in_progress` guardrail, Art.18 not frozen, registry acceptable). Closes the Rule 25 "snapshot, never re-check" pattern via a type-level forcing function (`GateClearance<"pre-delivery">` brand) + per-enqueue LIVE re-clearance before each delivery. Excellent.
- **RevealArtifactBundle** (`src/bundle/assemble.ts`): 15 top keys in exact §4.1 order (asserted), keccak256(utf8(jcs(...))) digest (§4.1 — verified `@cealis/v3-custody/.../jcs-canonicalize.ts` uses `keccak_256`, NOT sha256), `not_configured` issuer/provenance (§4.6), `bundle_version=s2-5.1` (§4.8), two-pass self-referential digest. Per-recipient positive allow-list + `COMBINER.RECIPIENT_SELECTOR_INVALID` on missing field (§3.4).
- **Webhook signer** (`src/webhooks/signer.ts`): JCS-canonical body, HMAC over §7.2 preimage, 300s window, constant-time verify, fail-closed on non-JCS-compatible envelope.
- **Refusal codes** (`src/types/refusal.ts`): exactly 0x01–0x0A (10), encrypted-reason for 0x02/0x03, advisory-only 0x0A, correct labels (§10.4).
- **Webhook taxonomy** (`src/types/webhook-events.ts`): all 18 event types verbatim (§7.1); event `data` carries only authorizationId/h_commit (§3.3/§7.5 — no σ/share in payloads).
- **Error model**: 12 categories (§1.4) present in `src/errors/categories.ts`; Problem+JSON shape; redaction allow-list (`src/redaction/safe-refs.ts`) = exactly the §10.2 safe-ref keys + FORBIDDEN_TOKEN_PATTERNS; manifest sanitizer recursively strips + throws on share/DEK/plaintext (`src/manifest/sanitize.ts`).
- **Tier matrix** (`src/types/tier-behavior.ts`): full 12-axis × 4-class NORMATIVE matrix verbatim from §12 (foundation-tested 12×4).
- **Mode 3 rejection**: `COMBINER.MODE_3_NOT_SHIPPED_AT_V2` + `rejectMode3` wired (§3.6/§4.4).
- **Idempotency** (`src/auth/idempotency-middleware.ts`): 24h TTL, scope-keyed, digest-conflict → `IDEMPOTENCY_KEY_CONFLICT` (§1.5).
- **Subject API**: vault-blob scoped by `user_id:h_commit` (cross-partner unlinkability §6.2), 404 on miss, no DEK returned. Partner shred-request enforces §8.4 authority (Joint/Operator only else 403).
- **Auth-shape conformance harness**: `tests/integration/openapi-runtime-cross-check.test.ts` cross-checks canonical.yaml paths+methods+dual-auth against actual Fastify `hasRoute` AND the RouteRegistry. canonical.yaml (`src/openapi/canonical.yaml`) is a faithful verbatim extract of App. A. This test PASSES, proving the actually-bound route paths/auth match the spec.

## DEVIATIONS

### D1 [MEDIUM] Production server factory mounts only ~5 of 29 canonical endpoints
`src/server/index.ts createFastifyApp()` mounts only: verify routes (3), `/internal/reveal/initiate`, `/healthz`. The ingest/partner/subject/vault/pre-sigma/webhook handler-register functions (`registerIngestRoutes`, `registerPartnerRoutes`, `registerSubjectRoutes`, `registerVaultRoutes`) exist and are spec-correct, but are invoked ONLY in integration tests — not in the production app factory. `src/server/bin.ts wireProductionDeps()` deliberately throws "NOT YET WIRED" (R2b worker-2/4 boundary). So a booted server today serves almost none of the partner/subject/ingest surface.
- spec_ref: §2–§9 (full surface) · code_ref: `src/server/index.ts:89-114`, `src/server/bin.ts:58-66`
- This is a documented, intentional scaffold state (Rule 12 fail-loud rather than half-wired). It is a maturity/wiring gap, not a logic defect — the route logic is implemented and tested. Flagged because a reader cannot run the spec'd API end-to-end against the production factory at HEAD.

### D2 [LOW] `OPERATION_TO_PATH` metadata table drifts from actual handlers + canonical.yaml
`src/types/operation-ids.ts` `OPERATION_TO_PATH` has 4 paths that disagree with both the spec/canonical.yaml AND the real handlers:
- `getPartnerObligationStatus`: table `/v1/partners/me/obligations/:obligation_id` vs handler `:obligationId` (spec param `obligationId`).
- `getPartnerShredStatus`: table `/v1/partners/me/shred-requests/:shred_request_id` vs handler+spec `/v1/partners/me/shreds/:h_commit`.
- `getVerificationNetworks`: table `/v1/verify/networks` vs handler+spec `/v1/verification/networks`.
- `getSdkVersions`: table `/v1/verify/sdk-versions` vs handler+spec `/v1/verification/sdk-versions`.
Also the table marks `getVaultRetention` and `verifyArtifactBundle` single-auth, but spec App. A gives the former dual (partner+subject) and the latter public (`security: []`). The ACTUAL handlers and canonical.yaml are spec-correct; the cross-check test only compares operationId NAMES + canonical-vs-runtime (not this table), so the drift is uncaught. Latent foot-gun if a future wiring step trusts `OPERATION_TO_PATH`.
- spec_ref: App. A (lines 1469-1493, 1619-1655) · code_ref: `src/types/operation-ids.ts:100-120`

### D3 [MEDIUM] Server-side attestation verify trusts client-supplied check results; no real on-chain DCAP/registry verification
`verifyAttestationPreflightOrThrow` (`src/g4/preflight-recompute.ts`) checks digest/context/header binding and that the client CLAIMED `status:"pass"` on the four checks — it does not independently re-derive the checks against live DCAP quote validity, on-chain `G4AuthorityRegistry`/`LitAssignmentRegistry`/G3-committee state. The attestation builder (`src/g4/attestation-builder.ts`) emits synthetic `status:"pass"` checks with a hardcoded zero-address `registry_address`. Spec §2.4 requires actual DCAP/zkDCAP/registry verification server-side; §2.2 frames server verify as defense-in-depth but still expects it to exist. Real registry/quote verification is S2-3/M8 territory and explicitly deferred.
- spec_ref: §2.2 line 301, §2.4 lines 324-334 · code_ref: `src/g4/preflight-recompute.ts:41-77`, `src/g4/attestation-builder.ts:98-114,156-173`
- Documented Phase B boundary, but the client-trusted "pass" path means the four-check security gate is not yet a real gate at HEAD.

### D4 [LOW] SD pipeline not integrated in ingest path; `sd_output` always `not_configured`
`createModeAIngestion` hardcodes `sd_output: { status: "not_configured" }` (`routes-create-mode-a.ts:612`). The response schema supports the §2.6 `{status:"failed", escrow_committed:true}` asymmetric-isolation shape, but no code path produces SD output or the failure shape — SD (S2-7) isn't wired into ingestion. SD asymmetric isolation (§0.7/§2.6 — SD fails while escrow commits) is therefore untested at the API layer because SD never runs.
- spec_ref: §2.6 lines 383-384 · code_ref: `src/ingest/routes-create-mode-a.ts:612`

### D5 [LOW] mTLS for regulated/legal-effect B2B ingestion not enforced (placeholder)
`assertAuthAllowed` (`routes-create-mode-a.ts:462-475`) only rejects consumer-PDA partner-HMAC; the mTLS requirement for regulated/legal-effect (§1.3, §2.4, §2.7, §12 b2b_ingestion row) is a comment "M8 wires certificate validation; Phase B only carries the mTLS-required fact." No cert validation occurs.
- spec_ref: §1.3, §2.7, §12 b2b_ingestion · code_ref: `src/ingest/routes-create-mode-a.ts:474`

### D6 [LOW] Partner-request raw-body capture relies on a fallback re-serialization
`rawBodyFromRequest` (`hmac-middleware.ts:143-148`) prefers `request.rawBodyBytes` but falls back to `JSON.stringify(request.body)`. If the raw-body capture plugin isn't wired in production, the verifier hashes re-serialized bytes that may differ from on-wire bytes, invalidating valid signatures (same byte-exactness concern §7.5 raises for webhooks). Tests pass because client+server stringify identically. Production must wire raw-body capture.
- spec_ref: §1.2 (sha256(raw_request_body)), §7.5 · code_ref: `src/auth/hmac-middleware.ts:143-148`

### D7 [LOW] Combiner-manifest GET does not re-verify §3.1 live preconditions
`getCombinerManifest` (`src/reveal/routes-get-manifest.ts`) returns the stored manifest if present; §3.1 ("returns a CombinerManifest only when all preconditions hold") is enforced upstream at manifest WRITE time + re-checked per-enqueue by the coordinator, but the READ path doesn't re-check live shred/Art.18 state. Also uses `REQUEST_MALFORMED` (400) + authorizationId-as-correlationId when the manifest isn't ready (arguably 404/409). Low risk given the coordinator's per-enqueue live re-clearance, but a pedantic §3.1 read expects the read path to re-verify.
- spec_ref: §3.1 lines 441-451 · code_ref: `src/reveal/routes-get-manifest.ts:19-31`

## Notes / non-issues
- `src/server/index.ts:6` file-top comment says `GET /v1/sdk-versions` — STALE COMMENT only; the actual handler binds `/v1/verification/sdk-versions` (spec-correct). Not a path bug.
- Verify-artifact-bundle endpoint correctly fails-closed structural-only unless `acknowledge_structural_only:true`, with explicit "use @cealis/verify-sdk locally" warning (addresses prior TS-API-F-06). Good (§9.1 offline-first SDK is the enforcement path; server endpoint is structural debug only).
- BP-N-S2-5-2/3 (schema V1-leakage, credential-table split) are spec-acknowledged Stage-3 migration items, not conformance defects.
