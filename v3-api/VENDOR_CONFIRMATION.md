# `@cealis/v3-api` — Vendor Confirmation

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

Stage-3 M5 ship state recorded 2026-05-11. This document captures the locked vendor + dependency choices, the surfaces that are operational at M5, and the surfaces that are deliberately deferred to M8 internal demo per the Rule 44 mid-build verification rule.

## Locked dependencies

| Surface | Pin | Notes |
|---|---|---|
| HTTP framework | `fastify@5.2.x` | V1 carry; TypeBox schemas + Swagger plugins (`@fastify/sensible`, `@fastify/cors`, `@fastify/rate-limit`, `@fastify/swagger`, `@fastify/swagger-ui`) |
| ORM | `drizzle-orm@0.36.x` + `pg@8.13.x` + `postgres@3.4.x` | V1 carry; Postgres 16 target |
| Queue | `bullmq@5.x` + `ioredis@5.4.x` | Webhook delivery + dead-letter + 90d retention |
| WebAuthn | `@simplewebauthn/server@13.x` | Passkey challenge + verify + session |
| Crypto hashes | `@noble/hashes@1.8.0` | HMAC + SHA-256; consistent with M3/M4 |
| Curves | `@noble/curves@1.9.7` | Imported only via `m1-imports.ts` facade (not re-imported elsewhere) |
| Canonicalization | `canonicalize@2.0.0` | RFC 8785 JCS; same pin as M3/M4 — preserves byte-deterministic bundle digest |
| Chain client | `viem@2.21.55` | Same pin as M3/M4 — `RevealAuthorized` event decode + chain anchor calldata |
| Schemas | `typebox@0.34.x` | Fastify TypeBox schemas; OpenAPI auto-derive |
| Logger | `pino@9.x` | Redaction-aware formatter (`src/redaction/log-sanitize.ts` filter) |

Workspace dependencies (`workspace:*`): `@cealis/v3-crypto`, `@cealis/v3-custody`, `@cealis/v3-configurator`. All consumed exclusively through `m1-imports.ts` / `m2-imports.ts` / `m3-imports.ts` / `m4-imports.ts` facades — never direct.

## Operational at M5

- **29 OpenAPI operationIds** wired into Fastify route registry. `src/openapi/canonical.yaml` extracted verbatim from S2-5 App. A; boot-time cross-check runs in `tests/integration/openapi-runtime-cross-check.test.ts`.
- **18-event webhook taxonomy** wired into `src/webhooks/event-bus.ts`; signer (HMAC over `utf8(timestamp) "." raw_body`) at 100% coverage; retry policy `[1s, 2s, 4s, 8s, 16s]` with jitter + max 5 retries + dead-letter; 90-day retention sweep.
- **10-code G4 refusal enum** with `reason_visibility` discriminator (`encrypted` for 0x02/0x03 Art. 17/18, `plaintext` for the rest). `0x0A` advisory non-blocking per §10.4.
- **15-key RevealArtifactBundle** assembly per §4.1 + App. B; byte-deterministic JCS canonicalization verified by 2-run identity test.
- **§12 NORMATIVE Per-PDA-Tier behavior matrix** (12 axes × 4 operational classes: `consumer / b2b_partner / regulated / legal_effect`) locked as `TIER_BEHAVIOR_MATRIX` constant; enforced at ingest (`g4_phase`, `b2b_ingestion`, `preflight_attestation`), at reveal (`combiner_context`, `sd_cleartext`), at webhook (`webhook_payloads`), at shred (`shred_request_auth`), and at audit export.
- **Mode A** TEE-ingest is the shipping ingestion path. **Mode B** + **Mode B+SD** both rejected with `409 SCHEMA.MODE_B_RESERVED` per §2.8.
- **Art. 18 enforcement** flows through G4 refusal `0x03` + `g4.refused` webhook with `reason_visibility: "encrypted"` + `encrypted_reason_ref`. NO REST freeze endpoint (internal legal-constraints rules (not exported) §Art. 18 is enforced via G4RefusalRegistry duration, not a freeze handler).
- **Reveal is event-driven** — `src/combiner-orchestrator/event-listener.ts` subscribes to M2 `RevealAuthorized`. NO `POST /v1/reveals` route.
- **Pre-σ session binding** (`src/pre-sigma/session-bind.ts`) links subject confirmation step to subsequent Mode A ingestion via `pre_sigma_session_id` consumed one-time.
- **`api_version` + `commit_version: "0x0302"`** kept distinct per §1.1 — never conflated.
- **HMAC canonical-request** shape per §1.2 verbatim; 300s replay window + 24h nonce-replay-store.
- **8-scope partner API** enforced at middleware (`src/auth/scope-enforce.ts`).
- **Redaction allow-list** (9 keys verbatim from §10.2 line 1014) is the only safe-ref shape that may appear in errors / logs / webhooks; PII filter is Pino-integrated.

## Deferred to M8 internal demo (per Rule 44)

| Surface | M5 state | M8 wiring |
|---|---|---|
| Live partner HMAC credentials | Mock partner stored in test fixture | Real partner config via `/v1/partners` admin path (Cealis-internal) |
| Live webhook external delivery | Mock receiver in same test process | Real partner-hosted endpoint URL + retry observation |
| Live vault backend | Mock storage adapter | S3/R2/IPFS per PDA config |
| Live IPFS pinner | Carries M4 offline-deterministic mock | Live pinner (Cealis primary + partner mirror + optional Filecoin) |
| Live partner mTLS certs (regulated/legal_effect) | Mock cert chain | Real cert provisioning + revocation list |
| G4 Phase 2 (rented TEE) | Phase 2 path schema + DCAP quote decoder surface; no live enclave | Live rented TEE (deferred to partner-pilot per §11) |
| Sealed-code G4 reproducible build | Architecture defined; no reproducibility verification yet | Nix or Docker reproducibility CI (M3 carry-over) |
| Live Base Sepolia + mainnet anchoring | Offline `registerPDA` calldata builder + event-payload mock | Live chain anchoring (carries M2 PRO-471) |

## Test surface

- **41 v3-api test files / 132 tests** (foundation + unit + integration), all green.
- **5 verify-sdk test files** (verify-artifact-bundle, verify-sd-output, verify-webhook, all-15-checks, offline-independence), 96.17% coverage.
- **18 v3-api integration tests** spanning ingest (4) / reveal+bundle (5) / partner+subject+webhooks+auth (9).
- **7 cross-surface integration tests** under Phase E namespace: openapi-runtime-cross-check, full-ingest-to-bundle-to-sdk-verify, sdk-offline-no-cealis-network, art-18-defer-end-to-end, all-5-archetype-fixtures, retention-floor-respected, shred-cascade-blocks-future-reveal.

## Anti-drift assertions (M5 Phase F tripwires green)

1. No σ / Shamir / DEK / file_key in webhook bodies, redaction outputs (except as filter identifiers), auth surfaces, or error bodies.
2. `S2_5_<SURFACE>.<CODE>` stage-code strings appear only in `src/errors/`.
3. No plaintext Art. 17 / Art. 18 refusal reasons in source — `0x02` / `0x03` always carry `reason_visibility: "encrypted"` + `encrypted_reason_ref`.
4. No Cealis URL hard-coded in `@cealis/verify-sdk` — partner-supplied RPC reader only.
5. 29 operationIds present in `src/openapi/canonical.yaml`.

## Open backprop items (carried forward to M6/M7/M8 backprop batch)

- **BP-N-S2-5-1** σ-doctrine cleanup at the S2-1 layer (cross-spec terminology consistency).
- **BP-N-S2-5-2** Orchestrator schema migration plan for V1→V3 (not in M5 scope; V3 ships clean schema).
- **BP-N-S2-5-3** Partner API auth schema split (signing-secret vs webhook-secret separation) — implemented in M5 DB schema, recorded for cross-spec consistency.
- **chain-anchor / reveal route coverage** (70-87% range) — HTTP route handler and retry-policy edge paths under-exercised. Non-blocking; M8 integration testing will exercise.

---

**Ship gate satisfied:** drand-only G3 + Lit fixture-backed adapter + G4 Phase 1 sealed-code is the M8 internal-demo configuration. dcipher SDK pinning + G4 Phase 2 hardening land before partner pilot (M3 carry-over + M7).
