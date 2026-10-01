# SPEC-COMPLIANCE-GUARD-M5

**Mission:** M5 — Ingestion + Delivery API (S2-5).
**Authored:** 2026-05-11 at Phase A (dw-worker, mode `acceptEdits`).
**Scope:** Anti-drift checklist for Codex chunks B/C/D/E. Every section below is a LOCKED constant or NORMATIVE rule. Phase F tripwire greps assert.

---

## §0 — Spec body vs PHASE-PLAN drifts caught at Phase A

PHASE-PLAN §0 enumerated 12 sanity-check items. Phase A grep-verified the spec body and recorded outcomes:

| # | PHASE-PLAN claim | Spec body verification | Resolution |
|---|---|---|---|
| 1 | "Brief says 27, App. A has 29" | `grep -c operationId: docs/specs/ingestion-delivery-api-spec.md` = **29** verified | LOCKED in `src/types/operation-ids.ts` |
| 2 | "18 webhook events" | §7.1 lines 805-824 verbatim count = **18** verified | LOCKED in `src/types/webhook-events.ts` |
| 3 | "10 G4 refusal codes" | §10.4 + S2-2 §14 (0x01-0x0A) = **10** verified | LOCKED in `src/types/refusal.ts` |
| 4 | "15 bundle top-level keys" | §4.1 lines 519-534 verbatim = **15** verified | LOCKED in `src/types/reveal-artifact-bundle.ts` |
| 5 | "12 error categories" | §1.4 lines 189-202 verbatim = **12** verified | LOCKED in `src/errors/categories.ts` |
| 6 | "8 partner scopes" | §5.1 lines 661-668 verbatim = **8** verified | LOCKED in `src/types/scopes.ts` |
| 7 | "Tier matrix 12×4, brief omits" | §12 lines 1083-1096 verified — 12 behavior rows × 4 operational classes | LOCKED in `src/types/tier-behavior.ts` |
| 8 | "App. B = 15 checks + overall" | App. B lines 2636-2652 verbatim = **15** named checks + `overall: VerifyStatus` | LOCKED in `src/types/reveal-artifact-bundle.ts` `VERIFY_ARTIFACT_CHECK_NAMES` |
| 9 | "g4.refused emits encrypted reason for 0x02/0x03" | §10.4 lines 1032-1043 verbatim | LOCKED in `src/types/refusal.ts` `REASON_VISIBILITY` |
| 10 | "CombinerManifest fields not enumerated in §3.1" | App. A lines 1949-1968 — 16 required fields verbatim | LOCKED in `src/types/combiner-manifest.ts` |
| 11 | "schema-mapping-path V1 vs M5" | Resolved per PHASE-PLAN: M5 implements from scratch, no V1 carry needed | NOT a Phase A item |
| 12 | "§14.3 BP-N candidates" | BP-N-S2-5-1/2/3 — backprop to other specs, not M5 deliverables | NOT in M5 scope; carry-forward |

**Additional drift caught during Phase A authoring:**

- PHASE-PLAN A3 wording "7 topics" — corrected to "7 ABI inputs (3 indexed topics + 4 unindexed data fields = 4 LOG topics total counting signature)". `src/m2-imports.ts` JSDoc + foundation test `m2-abi-smoke.test.ts` use the precise wording.

- **M4 fixtures gap (BACKPROP-CANDIDATE for Phase F):** PHASE-PLAN A5 expected `@cealis/v3-configurator/fixtures` to resolve as a TypeScript module via M4's package.json `./fixtures` subpath export. The subpath IS declared but M4's `tsconfig.json` excludes the `fixtures/` source directory from compilation (`"exclude": ["node_modules", "dist", "tests", "fixtures"]`), so the dist target at `dist/fixtures/app-a/index.js` does not exist. Phase A worked around by removing the fixtures import from `m4-imports.ts` (kept the comment + Phase E re-introduction note). The internal Phase E build brief instructs the build to load fixtures via source-file pointer (`v3-configurator/fixtures/app-a/index.ts`) using a relative path the test runner can resolve, OR Phase F may issue an M4 rebuild that produces the dist target. This is NOT a Phase A blocker — types catalog passes, and fixtures are integration-test territory.

---

## §1 — 29 OpenAPI operationIds (NORMATIVE)

Verbatim from App. A. Locked in `src/types/operation-ids.ts` `OPERATION_IDS`. Foundation test `operation-ids-catalog.test.ts` asserts count = 29.

Phase F tripwire (`grep -c operationId: src/openapi/canonical.yaml`) must return ≥29.

Phase B/C/D adding new routes MUST amend `OPERATION_IDS` + amend `src/openapi/canonical.yaml` + amend App. A in the spec — drift in either direction fails build per §1.7.

---

## §2 — 18 webhook events (NORMATIVE)

Verbatim from §7.1. Locked in `src/types/webhook-events.ts` `WEBHOOK_EVENT_TYPES`.

Every event has `event_id, schema_version, event_type, created_at, partner_id, pda_id, data` envelope. `data` discriminator: contains `h_commit`, `authorizationId`, or both.

Retry policy: 1s, 2s, 4s, 8s, 16s with jitter; max 5; success on 2xx within 30s; dead-letter after exhaustion; metadata retained 90 days.

---

## §3 — 10 G4 refusal codes + reason_visibility discriminator (NORMATIVE)

Verbatim from §10.4 + S2-2 §14. Locked in `src/types/refusal.ts`.

- 0x01 legal_compel — plaintext
- 0x02 art_17_erasure — **encrypted**
- 0x03 art_18_restriction — **encrypted** (NO REST freeze endpoint)
- 0x04 integrity_fail — plaintext
- 0x05 chain_mismatch — plaintext
- 0x06 plugin_deprecated — plaintext
- 0x07 authority_deprecated — plaintext
- 0x08 dsl_deprecated — plaintext
- 0x09 oracle_deprecated — plaintext
- 0x0A opt_out_active — plaintext, **advisory (non-blocking)** — G4 still signs

Phase D webhook `g4.refused` payload includes `reason_code`, `reason_label`, `reason_visibility`. For encrypted, `encrypted_reason_ref` replaces plaintext reason; for plaintext, no reason text is emitted (the label itself is the only safe field).

---

## §4 — 15-key RevealArtifactBundle (NORMATIVE)

Verbatim from §4.1 + App. B lines 2553-2605. Locked in `src/types/reveal-artifact-bundle.ts` (mirror of `verify-sdk/src/types.ts`).

Keys in order: bundle_version, canonicalization, authorization, pda, recipient, plaintext, issuer_attestation, provenance, sigma_block, chain_proofs, registry_snapshots, shred_state, sd_refs, verification, pii_statement.

`pii_statement` literal: `"recipient_filtered_plaintext_after_valid_reveal"`.
`bundle_version` current: `"s2-5.1"`.
`canonicalization.hash`: `"keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))"`.

---

## §5 — Per-PDA-tier behavior matrix 12 × 4 (NORMATIVE — largest Phase A drift catch)

Verbatim from §12. Locked in `src/types/tier-behavior.ts` `TIER_BEHAVIOR_MATRIX`. Foundation test `tier-behavior-matrix.test.ts` asserts 12 axes × 4 classes.

This was the LARGEST single drift in PHASE-PLAN §0 sanity — the single-shot brief omitted §12 entirely. Phase B (ingest), C (combiner manifest + bundle), and D (webhook payloads + shred auth + audit export) MUST consult this matrix per-axis. The universal tripwire statement (`UNIVERSAL_TRIPWIRE_STATEMENT`) is the canonical wording.

Where trust tier (A/B/C from S2-4) and operational class (consumer/b2b_partner/regulated/legal_effect) conflict, STRICTER API behavior applies.

---

## §6 — 12 error categories + HTTP status map (§1.4)

Verbatim from §1.4. Locked in `src/errors/categories.ts`. Phase B/C/D throw via `problemFromCode(code, correlationId, partial)` or `throwProblem(...)`.

Special-case codes locked at Phase A in `src/errors/codes.ts`:

- `424 ATTESTATION.{LIT_ASSIGNMENT_MISSING, DCAP_INVALID, G3_PUBKEY_INVALID, G4_AUTHORITY_INVALID}` — §2.8 lines 410-413
- `409 SCHEMA.MODE_B_RESERVED` — §2.8 line 421 (incl. Mode B + SD per Rule 6b SD-D9)
- `422 SCHEMA.PDA_SCHEMA_MISMATCH` — §2.8
- `503 VAULT.UNAVAILABLE`, `503 CHAIN.ANCHOR_RETRY_EXHAUSTED` — §2.8
- `409 IDEMPOTENCY.KEY_CONFLICT` — §1.5
- `409 GOVERNANCE.G4_REFUSED` — §10.4 (with reason_code + reason_visibility discriminator)
- `423 GOVERNANCE.REGISTRY_DEPRECATED_PRE_AUTHORIZATION` — §3.6
- `423 GOVERNANCE.PHASE_1_REJECTED_FOR_PARTNER_READY` — §11 + §2.3
- `503 RETRY_EXHAUSTED.WEBHOOK` — §7.3
- `429 RATE_LIMIT.EXCEEDED` — §1.4
- `409 COMBINER.{GATE_AUTHORIZATION_MISSING, SUPERSEDED_COMMIT_LINEAGE_BROKEN, MODE_3_NOT_SHIPPED_AT_V2, RECIPIENT_SELECTOR_INVALID}` — §3.6

---

## §7 — 8 partner API scopes

Verbatim from §5.1. Locked in `src/types/scopes.ts`. Per-route scope binding in `ROUTE_SCOPE_REQUIREMENTS`. Phase D middleware enforces.

---

## §8 — OpenAPI/text drift = build failure (§1.7)

Phase A wrote `src/openapi/canonical.yaml` extracted **verbatim** from App. A spec body (lines 1243-2428 of the spec). 29 operationIds confirmed.

Boot-time + Phase F + Phase E integration cross-check: `assertCanonicalOperationIds()` throws on drift. Phase D Fastify route registration goes through `RouteRegistry`; closeout asserts coverage via `registry.assertCoverage()`.

---

## §9 — σ-as-authorization doctrine (cross-stack)

Per S2-1 line 44 + S2-5 §3.3 + §4.4 + §10.2:

- σ values MUST appear inside `RevealArtifactBundle.sigma_block` post-reveal.
- σ values MUST NOT be emitted on-chain by any S2-5 endpoint (per §3.3 + S2-2 line 1324).
- σ values MUST NOT appear in errors, logs, webhook payloads outside `sigma_block`, or audit exports (per §10.2 line 1004).

Phase F tripwire grep: `grep -rE "^[^\"']*sigma|σ" v3-api/src/ --include='*.ts'` returns ZERO matches in `src/{webhooks,redaction,auth,errors}/`.

---

## §10 — §10.2 redaction allow-list (PII contract)

Verbatim from §10.2 line 1014. Locked in `src/redaction/safe-refs.ts` `SAFE_REF_KEYS`:

```
authorizationId, h_commit, event_id, block_number, registry_ref, pda_id,
partner_id, artifact_digest, encrypted_diagnostic_ref
```

`pickSafeRefs(obj)` filters arbitrary objects to this allow-list. Phase D log formatter + webhook payload builder + Problem+JSON `safe_refs` consume.

Phase F tripwire greps:

- `grep -rE "sigma\|shamir\|DEK\|kdf\|file_key" v3-api/src/ --include='*.ts'` returns ZERO matches in `src/{webhooks,redaction,auth,errors}/` AND ZERO in webhook payload bodies or error bodies.

---

## §11 — Mode A only this milestone (§2.9)

Mode B is RESERVED. M5 `POST /v1/ingestions` rejects every Mode B request with `409 SCHEMA.MODE_B_RESERVED` (§2.8 line 421).

Mode B + SD (`mode=B AND sd_enabled=true`) returns the SAME `409 SCHEMA.MODE_B_RESERVED` per Rule 6b SD-D9 + S2-7 §1.5.

Phase B test asserts both rejection paths return the EXACT 409 code string.

---

## §12 — No `POST /v1/reveals` endpoint

Reveals are EVENT-DRIVEN from M2 `RevealAuthorized` (§3.1). M5's reveal surface is read-only:

- `GET /v1/reveals/{authorizationId}` (status)
- `GET /v1/reveals/{authorizationId}/delivery-manifest`
- `GET /v1/reveals/{authorizationId}/artifact-bundles/{recipient_ref}`

Phase C `src/combiner-orchestrator/event-listener.ts` subscribes to chain events; never triggered by a partner POST.

---

## §13 — No Art. 18 REST freeze endpoint

Art. 18 enforcement = G4 refusal `0x03` (§10.4). The 90-day max + auto-expiry per internal legal-constraints rules (not exported) is enforced via `G4RefusalRegistry` entry duration on-chain, NOT via an OPERATOR_ROLE freeze in this package.

V1's `RevealManager.freezeReveals()` pattern does NOT carry into V2. Phase D MUST NOT add any `POST /v1/reveals/freeze` route.

---

## §14 — Phase 1 G4 = dev-scaffold + historical-verification only

Per §2.3 + §11 + S2-3 lines 202-209 + S2-4 line 540:

- Partner-ready and legal-effect PDAs REJECT Phase 1 commits (`423 GOVERNANCE.PHASE_1_REJECTED_FOR_PARTNER_READY`).
- Historical Phase 1 commits remain queryable + verifiable under their original phase metadata.
- Phase 1 responses carry `phase_trust_statement = "phase_1_registered_binary"` verbatim.

Phase B `src/g4/preflight-recompute.ts` enforces. Tier matrix `g4_phase` axis is the canonical strictness map.

---

## §15 — HMAC canonical-request shapes (§1.2 + §7.2)

Two DIFFERENT HMAC schemes. DO NOT SWAP:

**Partner request** (`src/auth/canonical-request.ts` `buildCanonicalRequest`):
```
METHOD "\n"
PATH_WITH_QUERY "\n"
X-Cealis-Timestamp "\n"
X-Cealis-Nonce "\n"
sha256(raw_request_body)
```

**Webhook signing** (`buildWebhookSignaturePreimage`):
```
utf8(X-Cealis-Timestamp) "." raw_request_body
```

Both use HMAC-SHA256 with the partner-specific secret. Replay window: 300s (§1.2 + §7.2). Nonce reuse window: 24h (§1.2).

Phase A foundation test `hmac-vector.test.ts` round-trips both vectors.

---

## §16 — 300s replay window + 24h nonce reuse window

`HMAC_REPLAY_WINDOW_SECONDS = 300` and `HMAC_NONCE_REUSE_WINDOW_SECONDS = 86400` locked in `src/types/auth.ts`. Phase D middleware enforces against `idempotency_keys` table.

---

## §17 — `api_version` AND `commit_version: '0x0302'` are distinct top-level fields

Per §1.1. NEVER conflate. `api_version` is the S2-5 surface version (e.g., `"1.0-draft"`); `commit_version` is the S2-1 cryptographic protocol version (currently `0x0302`). Phase B response builders MUST emit both as separate top-level fields.

---

## §18 — Phase A brief authoring discipline (M4 lesson 2 — BINDING)

Every E-depends-on-B/C/D reference in the internal Phase E build brief MUST point at source files, NOT embed specific function names. Pattern:

> "Import the combiner orchestrator from `v3-api/src/combiner-orchestrator/index.ts` — read the source for the exact export name and signature; if naming has drifted from this brief, follow the source."

Phase A worker grep-verified the Phase E build brief after authoring all 4 briefs that NO E-brief line contains a hard-coded function name from B/C/D.

---

## §19 — verify-sdk independence (§4.7 + §9.1 + App. B)

`verify-sdk/` is a SEPARATE package. Forbidden:

- `axios`, `node-fetch`, any HTTP client to Cealis
- `@cealis/v3-api`, `@cealis/v3-custody`, `fastify`, `drizzle-orm`, `bullmq`, `ioredis`
- Hard-coded Cealis URL anywhere in source

Allowed: `@cealis/v3-crypto` (workspace:*), `@noble/hashes`, `canonicalize`, `viem` ONLY.

Three exports per App. B:
- `verifyArtifactBundle(bundle, options?): Promise<VerifyArtifactResult>` — 15 named checks + overall
- `verifySdOutput(sd, options?): Promise<VerifySdResult>`
- `verifyWebhook(rawBody, headers, secret, now?): Promise<WebhookVerificationResult>`

Foundation tests `verify-sdk/tests/foundation/{independence,no-network-deps}.test.ts` enforce. Phase F tripwire greps confirm.

---

## §20 — `verifyWebhook` MUST verify HMAC BEFORE JSON parse

Per §7.5 line 864: parser differentials are a real attack surface. The SDK signature: `(rawBody: Uint8Array, headers, secret) => ...` — rawBody is bytes pre-parse. Phase E implementation MUST NOT JSON-parse first.

---

## §21 — 18-event webhook envelope shape verbatim

Per §7.1 line 826. Every event has `{ event_id, schema_version, event_type, created_at, partner_id, pda_id, data }`. `data` is the discriminator.

Phase D webhook emitter locked to `WebhookEnvelope<T>` from `src/types/webhook-events.ts`.

---

## §22 — Webhook retry policy verbatim

Intervals 1s/2s/4s/8s/16s with jitter; max 5; success on 2xx within 30s; dead-letter after exhaustion; 90-day retention.

Constants locked in `src/types/webhook-events.ts`. Phase D BullMQ queue configuration consumes.

---

## §23 — Subject session = SHA-256 hashed bearer, 7-day expiry, revocable

Per §6.1. Locked in `src/types/auth.ts` `SUBJECT_SESSION_TTL_SECONDS = 7*24*60*60`.

---

## §24 — `pre_sigma_session_id` binds confirmation to ingestion

Per §6.3. Phase D `src/pre-sigma/session-bind.ts` issues IDs; Phase B `POST /v1/ingestions` consumes via `pre_sigma_session_id` request field; one-time consume.

---

## §25 — Retention floor never silently shortened below configured (§15.1)

Per §15.1 + internal legal-constraints rules (not exported) lines 39-48. PDA-specific retention may be stricter or longer; API code may NOT shorten below configured floor.

Constants:
- Vault ciphertext: obligation + 3 years (§195 BGB).
- Wrapped shares: same as vault.
- Issuer plaintext PII: delete immediately after KYC + onboarding.
- Vault access logs: 12 months rolling.
- Orchestrator delivery logs: 3 years post-delivery.
- Gate/audit approval logs: 3 years post-approval.
- Webhook metadata: 90 days rolling.
- On-chain commitments: permanent.

Phase D vault retention endpoint + Phase B retention floor on ingest response enforce.

---

## Anti-drift one-line summary for Codex

> The 7 normative catalogs (29 ops, 18 events, 10 refusal codes, 12 error categories, 8 scopes, 15 bundle keys, 12×4 tier matrix) are LOCKED at Phase A in `src/types/` and `src/errors/`. Phase B/C/D MUST import-and-use, not re-derive. Foundation tests assert byte-identity. Spec body is canonical when in doubt.
