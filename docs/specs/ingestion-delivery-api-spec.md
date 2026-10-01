# Cealis V2 System, V3 Custody - Ingestion + Delivery API Specification (S2-5)

## §0 — Front Matter

### §0.1 Document identity

This document is the Stage-2 ingestion and delivery API specification for the Cealis V2 system with V3 custody architecture. It is S2-5 in the Stage-2 stack. Its job is to specify the external-facing API surfaces that partners, subjects, recipients, auditors, and Cealis services touch: G4 ingestion, subject pre-signing display delivery, reveal delivery orchestration, recipient combiner manifests, RevealArtifactBundle format, partner API, subject API, webhooks, vault access, retention, crypto-shredding coordination, and verification SDK contracts.

The canonical scope comes from the internal Stage-2 audit scope entry (not included in this export). That entry defines S2-5 as the partner-visible face of V2, covering the G4 ingestion endpoint, reveal delivery plus combiner protocol, artifact bundle format and verification, partner API, webhooks, verification SDKs, and vault access semantics. It explicitly scopes out cryptographic constructions, contract-level interfaces, commodity-gate integration, PDA emission, ceremony runbooks, and generated SDK references; those are imported by reference, not redefined here.

The system version is V2. V3 custody is the custody/key-holding subsystem inside V2. This document uses "V2 system, V3 custody" and does not use bare "V3" as a system-version label.

Mode A, TEE-ingest, is the shipping default. WP §G defines Mode A as the path where the subject client or partner backend uploads plaintext to the G4 ingestion endpoint, plaintext enters the Cealis TEE boundary, is encrypted into the age envelope, and is destroyed after processing (`docs/specs/wp.md` lines 640-646). Mode B, device-encrypt, is architected as a PDA+ capability but is not currently enabled in the shipping API surface (`docs/specs/wp.md` lines 652-670). S2-5 therefore specifies Mode A as live behavior and reserves Mode B fields for future enablement without defining it as a live endpoint.

### §0.2 Audience and reading order

Read by role first. Each role below gets the shortest path through the spec; cross-role sections become mandatory when an implementation touches that boundary.

**Partner integration engineer.** Read §1 conventions, §2 G4 ingestion endpoint, §5 Partner API, §7 webhooks, §8 vault access semantics, §9 verification SDKs, and App. A OpenAPI. The integration question is: how does a partner create onboarding links, submit data where B2B ingestion is authorized, receive SD outputs, observe lifecycle events, query status, and verify artifact bundles without needing to understand every cryptographic primitive.

**Cealis-internal API engineer.** Read §0 source ordering, §1 conventions, §2 ingestion, §3 reveal delivery surface, §4 artifact bundle, §10 errors, §11 G4 phase transition, §12 per-PDA-tier table, §15 storage discipline, and App. A. The implementation question is: what must every HTTP handler enforce before handing work to S2-1/S2-2/S2-3/S2-4/S2-7 components.

**Client-side engineer.** Read §2.2 pre-flight attestation, §2.7 B2B versus consumer ingestion differences, §6 subject API, §6.3 pre-σ verifier surface, and App. A endpoint fragments for subject flows. The client-side question is: what is fetched and displayed before plaintext leaves the client or before σ_subject is produced.

**External auditor reviewing for covert data leak.** Read §0.7 discipline anchors, §0.9 and §16 PII content statements, §1.4 confidential-error discipline, §2.2 plaintext pre-flight, §3 combiner location, §4 artifact format, §7 webhook payload discipline, §8 vault access, §10 abort discipline, §15 retention, App. A schemas, and App. C scope-outs. The audit question is: does any API path move plaintext, Shamir shares, DEK, subject passkey identifiers, sensitive refusal reasons, SD salts, or partner-confidential fields into logs, chain events, webhook metadata, or unauthorized responses.

### §0.3 Terminology discipline

**σ-as-authorization.** S2-1 line 44 is controlling: σ values are conventional verification signatures or attestation outputs over `(authorizationId, h_commit, block_hash)` under the gate authority state valid at the commit block; they are authorization evidence, not DEK material. A valid σ authorizes that gate's per-stanza wrap-decap path to release one Shamir share to the recipient combiner. σ bytes may appear in the RevealArtifactBundle after reveal. Secrecy attaches to released Shamir shares, decap material, DEK, and plaintext.

**Authorization signature / gate signature.** This document calls σ_Lit, σ_G3, σ_G4, and σ_conditional authorization signatures or gate signatures. It classifies σ as authorization evidence, not as secret material.

**Share-bearing response.** A gate response can contain σ plus the gate-side material required by the combiner to unwrap or admit one Shamir share. The σ portion is public-post-reveal evidence. The share-bearing portion is secret transit material and never appears in artifacts, logs, webhook bodies, or error contexts.

**Mode A.** TEE-ingest. Plaintext enters the G4 ingestion boundary briefly under attestation, is encrypted into the age envelope, and is destroyed after processing. Mode A supports SD because plaintext is present inside the TEE boundary at commit time (`docs/specs/wp.md` lines 642-648; `docs/specs/sd-spec-v2.md` lines 225-245).

**Mode B.** Device-encrypt. The subject device constructs the envelope locally and uploads ciphertext only. Mode B is architected but not currently enabled; it is incompatible with the TEE-side SD pipeline (`docs/specs/wp.md` lines 652-660; `docs/specs/sd-spec-v2.md` lines 83-85).

**Recipient combiner.** The recipient-side sealed binary or recipient-delegated combiner service (designed to operate outside Cealis custody) that verifies authorization signatures, decaps share-bearing stanzas, reconstructs the DEK via Shamir, decrypts the payload, and delivers per-recipient filtered plaintext. It is not Cealis-operated. S2-1 §14 lines 4053-4078 and S2-3 §9 lines 563-644 are controlling.

### §0.4 What this spec does not cover

This document does not specify cryptographic byte layouts, TAG constants, `commit_AAD`, AEAD, Shamir splitting, stanza wrapping, endpoint-attestation byte fields, or combiner pre-verification internals. Those are S2-1 (`docs/specs/cryptography-spec.md`).

This document does not specify Solidity contract surfaces, `RevealAuthorized` ABI, `ShredRegistry` ABI, `G4RefusalRegistry`, registry storage, Mode 3 rejection, UUPS upgrade discipline, or EIP-712 domain ownership. Those are S2-2 (`docs/specs/smart-contracts-spec.md`). If this document references EIP-712 reveal-manager surfaces, the domain name is `CealisRevealManager` per S2-2 lines 1445-1455.

This document does not specify Lit, dcipher, drand, G4 adapter internals, gate-recipient pubkey fetch mechanics, cross-vendor TEE libraries, SDK pins, or combiner binary hardening implementation. Those are S2-3 (`docs/specs/custody-integration-spec.md`).

This document does not specify PDA emission, PDA+ governance, boundary-decision rules, allowed surface class table, default tables, or internal configurator UI. Those are S2-4 (`docs/specs/configurator-pda-spec.md`).

This document does not specify SD circuits, Poseidon commitments, PLONK proof public input order, SD salts, SD revocation mechanics, or SD verification internals. Those are S2-7 (`docs/specs/sd-spec-v2.md`).

This document does not specify operator ceremony runbooks, incident playbooks, binary release ceremony, key rotation ceremony, G4 Phase 1 to Phase 2 cutover execution, Mode B activation ceremony, or generated SDK reference docs. Those belong to S2-6, S3-1, and S3-4.

### §0.5 Status of this document

Status: DRAFTED 2026-05-06 for Stage-2 authoring. Voice-pass pending. Sibling dependencies are S2-1 through S2-4 and S2-7 as drafted or back-propagated by 2026-05-05. The document is implementation-grade for Stage 3 API planning, but Stage 3 must still generate OpenAPI artifacts, SDK packages, conformance tests, and integration fixtures.

### §0.6 Source-of-truth ordering

For this document, source ordering follows the project rule: the maintainer's recorded design decisions first, the current Stage-2 stack next, and reference-only historical docs last. Inside the Stage-2 stack, the import order is:

1. S2-1 for cryptographic constructions and σ-as-authorization.
2. S2-2 for contract events, registries, halt/refusal, shred, and Mode 3 enforcement.
3. S2-3 for adapter behavior, combiner SDK, transport constraints, and version pins.
4. S2-4 for PDA configurability, class table, tier declarations, and partner-readable inspection.
5. S2-7 for SD onboarding output shape and asymmetric isolation.
6. WP §C/§D/§G/§H/§J/§K for system-level flow and framing.
7. The V1 interface-closure notes §J (V1 archive; not included in this repository) for V1 webhook HMAC/retry patterns only.

The V1 closure documents are reference-only where they conflict with the current Stage-2 stack. In particular, V1 guardian approval wording and V1 reveal event schemas do not override the V2 `RevealAuthorized` event from S2-2 lines 1302-1324.

### §0.7 Document discipline anchors

**Universal tripwire.** No API path may create a release path outside the on-chain-verified predefined condition. Reveal delivery APIs must verify a finalized `RevealAuthorized` event emitted only by ConditionEngine or its authorized emitter before any gate request is initiated. S2-2 lines 1302-1324 define the canonical event and its no-σ event boundary.

**σ-as-authorization.** API surfaces may transport and publish σ as authorization evidence after reveal, but must keep Shamir shares, decap material, DEK, plaintext, SD salts, and sensitive refusal details out of logs, errors, webhooks, and public events.

**Fail-closed.** Every handler that cannot prove attestation, PDA authorization, chain finality, challenge-window closure, shred state, registry snapshot, or auth scope must fail with a structured error and produce no plaintext, share, DEK, gate request, or artifact bundle.

**No PII on-chain.** API handlers that call chain write functions pass identifiers, roots, hashes, proof tokens, block refs, and registry refs only. They do not place plaintext PII, subject passkey pubkeys, σ_subject bytes, raw vault blobs, recipient delivery URLs, SD cleartext, or refusal plaintext on-chain.

**SD asymmetric isolation.** The SD pipeline can fail while escrow commit succeeds. S2-7 lines 209-219 are controlling: SD never influences `RevealAuthorized`, gate signing, `file_key` derivation, AEAD decryption, G4 refusal, or ShredRegistry state.

**PDA configurability.** The API reads PDA at every config-bearing step. It does not assume one KYC schedule, one recipient shape, one G3 path, one condition module, one shred authority, one trust tier, or one SD mapping. S2-4 §5 lines 497-589 is the canonical per-surface class table.

**Full-engine.** This document specifies the full API surface across condition modules and use cases. KYC enforcement is one composition. The same API contract must support time-lock, subject-initiated, heartbeat, oracle attestation, multi-party signal, dead-man's-switch, consent gate, composed modules, evidence, M&A, testament, archival, and partner-specific schemas.

### §0.8 Cross-reference index

| Source | Imported by S2-5 |
|---|---|
| S2-1 line 44 | σ-as-authorization terminology and artifact permissibility |
| S2-1 §6.4 lines 1843-1966 | AEAD payload and no partial plaintext on tag failure |
| S2-1 §6.5 / §4.7 lines 1021-1030, 1968-1972 | subject-side pre-σ verifier obligation |
| S2-1 §10 lines 2657-2730 | σ_conditional modes and Mode 1 delivery shape |
| S2-1 §11 lines 2968-3195 | endpoint attestation four-check sequence and PII-none statement |
| S2-1 §14 lines 4043-4218 | combiner location, pre-verify checklist, share secrecy, abort discipline |
| S2-1 §16 lines 4624-4864 | error taxonomy, no σ/share/plaintext in errors |
| S2-2 §10 lines 1227-1280 | shred authority, guardrail, triple block, vault deletion handoff |
| S2-2 §11 lines 1282-1300 | Mode 3 reserved enforcement |
| S2-2 §12 lines 1302-1351 | `RevealAuthorized` event and idempotency fields |
| S2-2 §14 lines 1398-1443 | pause/halt and G4 refusal reason codes |
| S2-3 §2 lines 171-230 | reveal runtime topology, phase matrix, cross-vendor and gate-recipient pubkey lifecycle |
| S2-3 §9 lines 563-644 | combiner SDK contract and hardening requirements |
| S2-3 §11 lines 680-713 | dependency version pin discipline |
| S2-4 §3-§5 lines 250-590 | boundary rule, verification gate, class table |
| S2-4 §11 lines 971-999 | trust-tier taxonomy and artifact carriage |
| S2-7 §1-§2 lines 129-257 | SD output states, errors, isolation, synchronous onboarding response |
| V1 interface-closure notes §J (V1 archive) | webhook HMAC, timestamp replay window, retry pattern |
| Internal legal-constraints policy (restated in §0.9 and §15) | retention periods |

### §0.9 PII content statement

S2-5 handles the largest PII surface in the Stage-2 stack because Mode A ingestion receives plaintext and subject-facing APIs may return vault blobs or audit exports to authenticated subjects. Plaintext PII crosses the G4 ingestion endpoint only after client-side attestation pre-flight succeeds. It exists inside the Mode A boundary long enough to validate schema, build the age envelope, optionally run SD, write the ciphertext envelope, and zeroize plaintext. It is not logged, not emitted in events, not included in errors, and not returned to partners except where the PDA explicitly configures SD cleartext outputs at commit or where a valid reveal produces a per-recipient artifact after the on-chain condition.

PII-bearing surfaces:

- Mode A plaintext upload request body.
- SD cleartext output in the onboarding response when the PDA configured `cleartext`.
- Subject retrieval of own encrypted vault blob metadata or audit export.
- Per-recipient plaintext block inside a RevealArtifactBundle after valid reveal.
- Partner-readable PDA inspection where schema names, recipient labels, jurisdiction, or delivery metadata can reveal context.
- Webhook payloads that carry pseudonymous identifiers, lifecycle states, and possibly encrypted diagnostic refs.

PII-minimized surfaces:

- On-chain commitment, reveal, shred, refusal, and registry events.
- Gate adapter evidence transcripts.
- Endpoint attestation objects.
- Partner status endpoints when no reveal has finalized.
- Error bodies, which use Problem+JSON codes and sanitized refs.

The controlling retention periods are: vault ciphertext for obligation duration plus 3 years, wrapped shares same as vault, issuer plaintext deleted immediately after KYC and onboarding, vault access logs 12 months rolling, orchestrator delivery logs 3 years post-delivery, guardian approval logs 3 years post-approval, webhook metadata 90 days rolling, and on-chain commitments permanent.

## §1 — Conventions

### §1.1 Versioning convention

The public API uses URL-path versioning: `/v1/...`. Breaking HTTP contract changes require `/v2/...`; additive fields may remain in `/v1` if existing clients can ignore them. The response header `Cealis-Api-Version` MUST echo the served version. Requests MAY send `Cealis-Api-Version: 2026-05-06` as a date pin; when present, the server must either serve exactly that compatible schema or return `409 api.version_unsupported`.

The cryptographic protocol version is separate from the HTTP API version. New commits use `commit_version = 0x0302` per S2-1 and S2-4 line 499. The ingestion response MUST include both `api_version` and `commit_version`. A partner SDK may upgrade HTTP transport while still verifying an old commit under its original `commit_version`.

Backward compatibility windows:

- Non-breaking field additions: no migration window required; fields must be nullable or ignorable.
- Deprecated endpoint aliases: minimum 180 days for partner-facing endpoints.
- Webhook schema changes: minimum 90 days parallel delivery if event payload shape changes.
- Cryptographic or artifact version changes: follow S2-1/S2-6 version ceremonies, not an API-only rollout.

### §1.2 Authentication convention

Partner API authentication uses API credentials plus request signing:

- `X-Cealis-Key-Id`: opaque partner key id.
- `X-Cealis-Timestamp`: Unix seconds.
- `X-Cealis-Nonce`: 128-bit random value encoded base64url.
- `X-Cealis-Signature`: `sha256=<hex HMAC-SHA256(signing_secret, canonical_request)>`.
- `Idempotency-Key`: required on all mutating endpoints.

The API key secret is stored server-side as a bcrypt hash. The signing secret is stored encrypted at rest and is never returned after creation. The existing orchestrator schema already models partner id, bcrypt API key hash, webhook URL, and encrypted webhook secret; Stage 3 may split request signing secret and webhook secret into separate records, but the security posture is the same: no plaintext long-lived secret in the database.

`canonical_request` is:

```
METHOD "\n"
PATH_WITH_QUERY "\n"
X-Cealis-Timestamp "\n"
X-Cealis-Nonce "\n"
sha256(raw_request_body)
```

Subject API authentication uses Passkey/WebAuthn-backed Bearer sessions. The bearer token is generated after a successful WebAuthn assertion and stored only as a SHA-256 hash with 7-day expiry and revocation flag. The existing `user_sessions` table states this directly.

Webhook authentication is separate. Partner endpoints verify Cealis-delivered webhooks with `X-Cealis-Signature` HMAC over the exact byte string `utf8(X-Cealis-Timestamp) "." raw_request_body`, using the 5-minute replay window inherited from the V1 interface-closure pattern.

### §1.3 Transport convention

All HTTP APIs require TLS 1.3. Partner-to-Cealis B2B ingestion for regulated or legal-effect PDAs requires mutual TLS in addition to request signing. Subject browser flows use TLS 1.3 plus WebAuthn challenge binding. Gate and combiner share-bearing channels follow S2-3 line 112: minimum TLS 1.3 with certificate pinning or mTLS; Noise or TEE-native secure channels are allowed if endpoint identity and forward secrecy are proven.

Plain HTTP, unauthenticated WebSocket, debug proxy forwarding, queue persistence of share-bearing gate responses, and browser storage of plaintext uploads are non-conforming.

### §1.4 Error model

HTTP errors use RFC 7807 `application/problem+json`.

Top-level categories:

| Category | HTTP | Meaning |
|---|---:|---|
| `REQUEST` | 400 | Malformed request, unsupported content type, invalid JSON, invalid field encoding |
| `AUTH` | 401/403 | Missing, expired, bad, or insufficient credential |
| `ATTESTATION` | 409/424 | Endpoint attestation, DCAP, registry, binary hash, or client pre-flight failed |
| `VAULT` | 404/409/503 | Vault object missing, retention state, already shredded, vault unavailable |
| `CHAIN` | 409/424/503 | Chain finality, event proof, registry read, condition, challenge, or shred state failed |
| `COMBINER` | 409/424 | Combiner manifest, σ verification, share threshold, artifact assembly, or Mode 3 rejection failed |
| `SCHEMA` | 422 | PDA schema, SD field mapping, payload classification, or recipient selector failed |
| `IDEMPOTENCY` | 409 | Idempotency key replay with divergent request body |
| `RATE_LIMIT` | 429 | Per-key or per-IP limit exceeded |
| `TRANSPORT` | 502/504 | Gate, vendor, vault, chain RPC, or webhook transport failure |
| `GOVERNANCE` | 409/423 | Registry tombstone, halt, refusal, pause, or phase restriction |
| `RETRY_EXHAUSTED` | 409/503 | Bounded retry budget exhausted |

Problem body:

```json
{
  "type": "https://docs.cealis.local/problems/attestation.endpoint_check_failed",
  "title": "Endpoint attestation check failed",
  "status": 424,
  "code": "ATTESTATION.ENDPOINT_CHECK_FAILED",
  "category": "ATTESTATION",
  "detail": "The G4 endpoint attestation did not match the registry state for the requested commit block.",
  "correlation_id": "01J...",
  "retryable": false,
  "safe_refs": {
    "authorizationId": "0x...",
    "h_commit": "0x...",
    "registry_ref": "0x..."
  }
}
```

Confidential-error discipline is normative. Error bodies and logs MUST NOT include raw σ values, partial σ bytes, Shamir shares, decap material, DEK, plaintext, partial `commit_AAD`, SD salts, SD witnesses, raw proof transcripts, passkey public keys, or sensitive refusal plaintext. S2-1 §16.15 lines 4832-4848 defines the same boundary for cryptographic errors. S2-5 applies it to HTTP, webhook, and vault errors.

### §1.5 Idempotency-Key convention

All mutating partner endpoints and all mutating subject endpoints that create durable or replay-sensitive server state require `Idempotency-Key`. WebAuthn challenge and assertion endpoints are the narrow exception: they are challenge-bound, authenticator-replay-bound, and short-TTL by construction, so replay returns an authentication result or error rather than a cached business response. Pre-σ confirmations, session revocation, onboarding-link creation, ingestions, and shred requests are idempotent.

The server stores the key, request digest, response body, status code, and expiry for 24 hours, matching the existing idempotency table design.

Replay with the same request digest returns the original response and status. Replay with a different digest returns `409 IDEMPOTENCY.KEY_CONFLICT`. Idempotency keys are scoped by partner id or subject id plus endpoint family. The same opaque key may be reused by two different partners without collision.

Reveal delivery idempotency uses `(authorizationId, h_commit, authorizationBlock)` as the workflow key per S2-2 lines 1326-1328. Webhook idempotency uses `(event_id, (h_commit || authorizationId))`.

### §1.6 Rate-limiting convention

Rate limits are enforced per API key, per subject session, and per source IP. Partner rows already include `rateLimit` as sustained requests per second. Responses use HTTP 429 with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`.

Rate-limit errors are liveness failures, not security downgrades. The server must not bypass attestation, chain, vault, or PDA checks to serve a request under load.

### §1.7 OpenAPI emission convention

Every endpoint enumerated in §2-§9 has a matching OpenAPI 3.1 fragment in App. A. Schema names in text and App. A are canonical: `Problem`, `AttestationPreflight`, `PreflightCommitContext`, `ModeAIngestionRequest`, `ModeAIngestionResponse`, `G4EndpointAttestationResponse`, `CombinerManifest`, `RevealArtifactBundle`, `PdaInspection`, `OnboardingLinkRequest`, `OnboardingLinkResponse`, `EscrowStatus`, `RevealStatus`, `ObligationStatus`, `SubjectSession`, `SubjectEscrowList`, `VaultBlobResponse`, `AuditLogExport`, `RetentionStatus`, `ShredRequest`, `WebhookEvent`, `VerifyArtifactRequest`, `VerifyArtifactResponse`, and `SdkVersionManifest`.

Stage 3 code generation must fail if text and OpenAPI drift in endpoint path, request schema name, response schema name, auth scheme, or required idempotency header.

## §2 — G4 ingestion endpoint (Mode A — shipping default)

### §2.1 Endpoint surface

Live endpoints:

- `GET /v1/g4/attestation`: fetch the current endpoint attestation candidate for a PDA, phase, and pre-upload commitment context.
- `POST /v1/ingestions`: submit a Mode A plaintext payload and commit metadata.
- `GET /v1/ingestions/{h_commit}`: read ingestion status and anchoring state.

`POST /v1/ingestions` accepts either subject-authenticated consumer submissions or partner-authenticated B2B submissions, depending on the PDA's ingestion mode and submitter policy. It never accepts live Mode B ciphertext as a Mode A request. A request with `ingestion_mode = "mode_b"` returns `409 SCHEMA.MODE_B_RESERVED` unless the PDA+ platform state has explicitly enabled Mode B through a later ceremony.

The request MUST carry:

- `Authorization` or partner HMAC headers.
- `Idempotency-Key`.
- `Cealis-Api-Version`.
- `Content-Type: application/json` for inline plaintext payloads or `multipart/form-data` with a `metadata` part plus a `plaintext_payload` file part for large payloads.
- `X-Cealis-Client-Attestation-Digest`: digest of the attestation object the client verified before transmitting plaintext.

The request body is `ModeAIngestionRequest`:

- `authorizationIdCandidate` (32-byte hex) or `authorization_nonce` from which server derives candidate.
- `preflight_commit_context` and `preflight_context_digest`.
- `pda_id`, `pda_version`, `partner_id`.
- `subject_commitment_v3` inputs or an issuer attestation ref sufficient to derive it under PDA Issuer mode.
- `sigma_subject` or `pre_sigma_session_id` when the subject-side verifier signs during the same flow.
- `schema_digest`, `payload_classification`, `payload`.
- `attestation_preflight` with the four check outputs.
- `recipient_acknowledgments` for conditional recipients where required by the pre-σ verifier.
- `sd_requested` inferred from PDA, not free-form partner override.

S2-1 §11 lines 2968-2987 define the four endpoint-attestation checks. WP §C lines 147-156 requires those checks client-side before plaintext transits.

### §2.2 Pre-flight client-side attestation verification protocol

Before plaintext leaves the client, all four checks fire client-side:

The client first constructs `PreflightCommitContext` from PDA inspection plus local payload metadata. The context contains `authorizationIdCandidate`, `pda_id`, `pda_version`, `partner_id`, `schema_digest`, `payload_digest`, `payload_canonicalization`, `pda_root`, `g3_choice`, `g4_phase`, `commit_block_number`, and `commit_block_hash`. `payload_digest` is the keccak-256 digest of the exact canonical plaintext bytes that will be sent to G4; it is a digest only and is safe to include in attestation metadata.

`commit_block_number` is the latest finalized Base block the client uses for this pre-flight, and `commit_block_hash` is the corresponding header hash. The client obtains the block hash from a Base RPC finalized/safe block header or from the chain-finality source named by the PDA. A G4 response may suggest a block, but the client must independently verify the block hash and finality. The server rejects stale, non-canonical, or non-final block hashes.

The pre-flight attestation object binds `preflight_context_digest`, not a final `h_commit` that the Mode A client cannot yet compute because G4 builds the ciphertext envelope after plaintext enters the attested boundary. G4 recomputes the digest before accepting plaintext, verifies that the submitted plaintext hashes to `payload_digest`, and only then produces the final age envelope and final `h_commit`. Reveal-time gate signatures still bind the final `(authorizationId, h_commit, block_hash)` tuple under S2-1/S2-3; commit-time pre-flight binds the context from which that final commit must descend.

The four checks are:

1. Lit V3 assignment record for `authorizationIdCandidate`.
2. Commit-time per-op DCAP quote from the assigned Lit/G4 TEE binding `preflight_context_digest` and `commit_block_hash`; reveal-time per-op DCAP and gate signatures bind the final `(authorizationId, h_commit, block_hash)`.
3. G3 committee pubkey for the selected dcipher or drand path at `commit_block_number`.
4. G4 authority attestation for Phase 1 or Phase 2 at `commit_block_number`.

The client computes `client_attestation_digest = keccak256(utf8(jcs(attestation_preflight_json_object)))` over the structured `AttestationPreflight` object and sends the same digest in `X-Cealis-Client-Attestation-Digest`. The digest binds the proof bundle to `authorizationIdCandidate`, `preflight_context_digest`, `commit_block_number`, and `commit_block_hash` before plaintext leaves the client.

This is not advisory. If any check fails, the client MUST NOT transmit plaintext. The server also re-verifies the submitted `attestation_preflight`, but server verification is defense-in-depth; it does not replace client-side verification.

Phase-specific detail:

- For Phase 1, the client verifies the G4 sealed-code binary hash and Ed25519 attestation against `G4AuthorityRegistry` state at the commit block.
- For Phase 2, the client verifies the DCAP quote, measurement, user-data binding, and on-chain zkDCAP verifier result.

The response from `GET /v1/g4/attestation` is not sufficient by itself. The client must verify the response against chain and registry state. A client that simply trusts the HTTP response is non-conforming.

### §2.3 Phase 1 path (sealed-code server)

Phase 1 exists for dev-scaffold and historical verification. Partner-ready and legal-effect PDAs require Phase 2 per S2-3 lines 202-209 and S2-4 line 540. When a PDA permits Phase 1, the ingestion API does the following:

1. Returns a Phase 1 attestation object from `GET /v1/g4/attestation` containing `phase = 1`, `binary_hash`, `effective_block`, `timestamp`, and an Ed25519 signature over the S2-1-defined G4 attestation preimage.
2. Requires the client to verify `binary_hash` against `G4AuthorityRegistry.getEntryAt(..., commit_block)`.
3. Opens an authenticated TLS 1.3 channel to the sealed-code endpoint.
4. Receives plaintext, validates schema, generates the commit-time DEK, builds the age envelope, Shamir-splits and wraps shares, writes ciphertext to vault, and zeroizes plaintext plus DEK plus Shamir polynomial coefficients.
5. Anchors `h_commit` on-chain and returns transaction refs.

Phase 1 responses must carry `phase_trust_statement = "phase_1_registered_binary"`. They must not represent Phase 1 as equivalent to Phase 2 TEE attestation for partner-ready or legal-effect use.

### §2.4 Phase 2 path (rented TEE)

Phase 2 is the normative partner-ready path. The endpoint returns and verifies:

- DCAP quote bytes.
- TEE vendor family.
- Enclave measurement.
- `user_data` binding to the authorization context.
- on-chain zkDCAP verification reference.
- `G4AuthorityRegistry` entry at the commit block.
- cross-vendor compatibility with Lit at reveal time, rechecked by S2-3 adapters.

The channel from client to G4 TEE uses TLS 1.3 with endpoint identity pinned to the attested enclave. For regulated or legal-effect B2B ingestion, mTLS is required. Plaintext enters only after the attestation object and channel binding verify. If quote verification fails, the server returns no alternate weaker ingestion path.

### §2.5 Request body schema — plaintext upload + commit metadata

`ModeAIngestionRequest` fields:

| Field | Required | Notes |
|---|---:|---|
| `pda_id` | yes | PDA reference from S2-4 partner-readable inspection |
| `pda_version` | yes | Bound into `pda_root` and commit metadata |
| `partner_id` | yes | Required even for subject-direct flows; derived from onboarding token if subject flow |
| `authorizationIdCandidate` | yes | 32-byte candidate; server may rederive and reject mismatch |
| `preflight_commit_context` | yes | `PreflightCommitContext`; client-built pre-upload context verified before plaintext transit |
| `preflight_context_digest` | yes | 32-byte digest of `preflight_commit_context`; must match the attestation object and server recomputation |
| `subject_commitment_inputs` | conditional | Issuer-mode-specific inputs or attestation ref |
| `sigma_subject` | conditional | Required unless `pre_sigma_session_id` points to just-completed verifier/sign flow |
| `schema_digest` | yes | Must match PDA schema |
| `payload_classification` | yes | PII class, Art. 9 flag, size, media type, schema version |
| `plaintext_payload` | yes | JSON, binary, or multipart part; never logged |
| `attestation_preflight` | yes | Four-check proof bundle |
| `client_attestation_digest` | yes | Digest echoed in header |
| `conditional_recipient_confirmations` | conditional | Required when PDA has conditional recipients |
| `idempotency_key` | header | 24-hour deterministic replay |

The server MUST recompute `preflight_context_digest` from `preflight_commit_context`, verify `payload_digest` against the received plaintext bytes before any envelope construction, and reject if the attested digest, header digest, request-body digest, or chain block snapshot differ.

The server MUST recompute `schema_digest`, PDA-derived `pda_root`, `recipients_root`, challenge windows, shred authority, G3 choice, G4 phase, and SD plan from the current PDA. Client-provided values are checked for equality, not trusted as authoritative.

### §2.6 Response body schema — h_commit confirmation and optional SD output

`ModeAIngestionResponse` fields:

- `api_version`
- `commit_version`
- `ingestion_id`
- `authorizationId`
- `h_commit`
- `pda_id`
- `pda_version`
- `partner_id`
- `vault_ref`
- `commit_tx_hash`
- `commit_block`
- `endpoint_attestation_digest`
- `g3_choice`
- `g4_phase`
- `retention_expires_at`
- `sd_output`
- `status`

`sd_output` is nullable. If SD is not configured, it is `{ "status": "not_configured" }`. If SD succeeds, it follows S2-7 output shape, including `sdMerkleRoot`, cleartext items, claim proofs, expiry, and revocation refs (`docs/specs/sd-spec-v2.md` lines 2140-2212). If SD fails while escrow commit succeeds, it is `{ "status": "failed", "failures": [...], "escrow_committed": true }` and the top-level ingestion response remains successful. This is required by S2-7 lines 209-219 and 245-257.

### §2.7 B2B vs consumer ingestion path differences

**B2B partner-submitted ingestion.**

- Auth: partner HMAC plus API key; mTLS for regulated/legal-effect PDAs.
- Subject consent: partner must supply σ_subject or a reference to a completed subject WebAuthn passkey ceremony.
- Submitter authorization: PDA must allow partner backend submitter in `submitter_sets_root`.
- SD output: returned to partner in the ingestion response if configured.
- Plaintext source: partner backend. The partner remains responsible for source-side collection legality and field accuracy.

**Consumer subject-direct ingestion.**

- Auth: onboarding token followed by Passkey/WebAuthn session.
- Subject consent: generated in the same client flow through the pre-σ verifier.
- Submitter authorization: subject must be an eligible submitter for the PDA.
- SD output: delivered to partner via response-to-partner channel or webhook, not shown to subject unless the PDA makes it subject-visible.
- Plaintext source: subject device/browser.

Both paths converge inside the same Mode A G4 ingestion boundary. The API difference is authentication, submitter authority, and response routing; the cryptographic commit surface is identical.

### §2.8 Error model

Attestation failures:

- Check 1 missing Lit assignment: `424 ATTESTATION.LIT_ASSIGNMENT_MISSING`.
- Check 2 DCAP invalid or user-data mismatch: `424 ATTESTATION.DCAP_INVALID`.
- Check 3 G3 gate-recipient KEM pubkey unavailable or mismatched: `424 ATTESTATION.G3_PUBKEY_INVALID`.
- Check 4 G4 Phase 1/2 authority invalid: `424 ATTESTATION.G4_AUTHORITY_INVALID`.

Other failures:

- Vault unavailable before chain anchor: `503 VAULT.UNAVAILABLE`, retryable.
- Vault write succeeds but chain anchor fails: server retries with same `h_commit` under idempotency. If retry budget exhausts, `503 CHAIN.ANCHOR_RETRY_EXHAUSTED`; vault object remains staged but unreleasable until anchor succeeds or cleanup ceremony removes it.
- Chain anchor succeeds but response lost: idempotency replay returns the successful response.
- Schema mismatch: `422 SCHEMA.PDA_SCHEMA_MISMATCH`.
- Mode B request to live Mode A endpoint: `409 SCHEMA.MODE_B_RESERVED`.
- SD failure: encoded only under `sd_output.failures` when escrow commit succeeds; top-level error only if escrow itself failed.

### §2.9 Mode B reserved-path note

Mode B needs future API fields:

- device-generated age envelope upload;
- device-side gate-recipient pubkey proofs;
- device-side endpoint attestation transcript;
- local Shamir split proof surface where required by auditor profile;
- Mode B explicit SD unavailability marker;
- client SDK binary hash and attestation-flow spec.

These fields are reserved but not live. Current `/v1/ingestions` MUST reject a Mode B commit request rather than attempting to coerce it into Mode A.

## §3 — Reveal delivery surface (combiner protocol)

### §3.1 Combiner location discipline

Reveal delivery begins only after:

1. `RevealAuthorized(authorizationId, hCommit, pdaRoot, authorizationBlock, authorizationTimestamp, challengeWindow, conditionRef)` is finalized on Base L1.
2. Any PDA challenge window has closed or resolved valid.
3. Shred state does not block the reveal.
4. Registry deprecation state at authorization block is acceptable.
5. PDA recipient policy identifies the recipient or delegated combiner location.

The recipient combiner is recipient-side or recipient-delegated and non-Cealis-operated. S2-1 lines 4053-4078 make this location discipline normative. S2-3 lines 632-644 require regulated recipients to use recipient-controlled TEE/HSM or equivalent sandbox where configured; consumer recipients may use audited process memory with an explicit risk statement.

`GET /v1/reveals/{authorizationId}/delivery-manifest` returns a `CombinerManifest` only when all preconditions above hold. It includes no plaintext, no Shamir share, no DEK, and no share-bearing gate response. It is a manifest for the recipient to contact gates and vault with verified identifiers.

### §3.2 σ gathering protocol

The recipient combiner gathers:

- σ_Lit plus Lit per-op DCAP quote and assignment proof.
- σ_G3 plus `g3_choice` marker and dcipher/drand verification evidence.
- σ_G4 plus phase marker and Phase 1 signature metadata or Phase 2 DCAP quote.
- σ_conditional vector where the PDA's conditional-recipient policy requires it.

The combiner contacts gates using S2-3 adapters. S2-3 lines 175-185 define the runtime order: G1 event, finality/challenge satisfaction, gate adapters request σ values, combiner verifies signatures/attestations/registries/pubkeys/envelope bindings, and then Shamir reconstructs `file_key`.

S2-5 does not require Cealis to proxy σ gathering. The default API returns endpoints, registry refs, and proof requirements; the recipient SDK contacts gate substrates directly. If a recipient delegates to a combiner service designed to operate outside Cealis custody, that service receives the same manifest and must meet the PDA's execution-context requirement.

### §3.3 σ transport and share-secrecy discipline

σ bytes are authorization evidence and may appear in the artifact after reveal. Transport still uses authenticated encryption because the gate response can include or enable access to share-bearing decap material, and because replayed or forged σ must not be admitted to the wrong stanza. S2-3 line 112 sets the minimum transport: TLS 1.3 with certificate pinning or mTLS, Noise, or TEE-native secure channels that prove endpoint identity and forward secrecy.

Rules:

- σ values MUST NOT be emitted on-chain by S2-5 endpoints. S2-2 line 1324 states no contract event emits σ, σ digests, gate partials, or DEK material.
- drand σ_G3 may be public by design. This is acceptable because Shamir share secrecy, not σ secrecy, protects the DEK.
- Gate response logs MUST store σ digests or transcript refs only, never raw σ bytes, and never share-bearing material. `RevealArtifactBundle.sigma_block` is the authorized post-reveal publication surface for σ evidence. S2-3 lines 116-117 define evidence without σ or shares.
- Recovered Shamir shares, decap material, Shamir interpolation state, DEK, and plaintext MUST be zeroized after plaintext-or-abort.
- The combiner never persists DEK and never writes plaintext to temporary files by default (S2-3 lines 624-644).

### §3.4 Per-recipient schema selectors

Every recipient in the PDA has a schema selector bound at commit time through `recipients_root` and `commit_AAD`. The delivery manifest returns each recipient's selector digest and human-readable summary if the requesting principal is allowed to see it.

After AEAD decryption, the combiner applies the selector to produce recipient-specific plaintext. Selectors are positive allow-lists, not redaction patches. A field absent from the selector is not delivered. A selector that references a field missing from the schema produces `COMBINER.RECIPIENT_SELECTOR_INVALID` and no bundle for that recipient.

This filtering happens after full plaintext decryption inside the recipient delivery boundary. The cryptographic payload has one DEK and one AEAD ciphertext per commit; partial cryptographic reveals are not a concept. S2-1 lines 4214-4218 make that explicit.

### §3.5 Multi-recipient delivery

For N recipients, the combiner emits N per-recipient bundles, each filtered by that recipient's schema selector and wrapped or delivered to that recipient's configured endpoint or account. WP §D lines 413-418 describes per-recipient JCS-canonicalized bundles.

Re-encryption occurs inside the combiner boundary:

- PASSKEY_ACCOUNT recipients receive in-app delivery inside the Cealis dashboard or equivalent authenticated client.
- WALLET_EOA recipients receive an age X25519-wrapped payload to their configured delivery pubkey and delivery URL.
- Delivery-only institutional recipients receive according to PDA recipient policy: webhook pull, secure file handle, partner vault inbox, or recipient-controlled storage.

N recipients means N distinct recipient pubkeys or authenticated account bindings. A shared plaintext URL for all recipients is non-conforming.

### §3.6 Combiner failure-mode surface

`GET /v1/reveals/{authorizationId}` and webhook events expose failure classes, not secrets:

- Gate refused or missing: `COMBINER.GATE_AUTHORIZATION_MISSING`.
- G4 refusal: `GOVERNANCE.G4_REFUSED` with reason code and encrypted reason ref where applicable.
- Registry deprecated before authorization: `GOVERNANCE.REGISTRY_DEPRECATED_PRE_AUTHORIZATION`.
- Registry deprecated after authorization: manifest records snapshot; in-flight reveal proceeds under S2-1/S2-2 rules unless G4 has an independent refusal reason.
- Shred finalized: `VAULT.COMMIT_SHREDDED` or `CHAIN.SHRED_FINALIZED`.
- Re-key lineage walk failed: `COMBINER.SUPERSEDED_COMMIT_LINEAGE_BROKEN`, mapping to S2-1 §15 recovery.
- Mode 3 encountered: `COMBINER.MODE_3_NOT_SHIPPED_AT_V2`.

Failure responses include `authorizationId`, `h_commit`, safe event refs, and correlation ids. They do not include σ, share, DEK, plaintext, partial AAD, or raw recipient delivery metadata.

## §4 — RevealArtifactBundle format

### §4.1 Container format

`RevealArtifactBundle` is JCS canonical JSON under RFC 8785. The canonicalized byte string is hashed as `artifact_bundle_digest = keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))`. A bundle is emitted per recipient.

Top-level keys:

1. `bundle_version`
2. `canonicalization`
3. `authorization`
4. `pda`
5. `recipient`
6. `plaintext`
7. `issuer_attestation`
8. `provenance`
9. `sigma_block`
10. `chain_proofs`
11. `registry_snapshots`
12. `shred_state`
13. `sd_refs`
14. `verification`
15. `pii_statement`

The bundle may be stored in vault delivery storage, downloaded by the recipient, and later supplied to `@cealis/verify-sdk`. The bundle is a reveal artifact, not a raw data dump: it carries the plaintext selected for that recipient plus evidence required to verify why release was authorized.

### §4.2 Authorization identifiers

`authorization` contains:

- `authorizationId`
- `h_commit`
- `commit_version`
- `authorization_block`
- `authorization_block_hash`
- `authorization_timestamp`
- `conditionRef`
- `challenge_window_seconds`
- `challenge_window_expired_at`
- `finalized_at`

The event fields match S2-2 lines 1308-1320. `authorizationId`, `hCommit`, and `pdaRoot` are indexed on-chain; S2-5 joins artifacts on these fields.

### §4.3 Per-recipient plaintext block

`plaintext` contains only the fields selected for the recipient:

```json
{
  "schema_selector_digest": "0x...",
  "schema_digest": "0x...",
  "content_encoding": "application/json",
  "fields": { "field_name": "value" },
  "field_hashes": { "field_name": "0x..." }
}
```

`field_hashes` are optional but recommended for large or binary payloads. They are computed over canonical field encodings. The bundle must not include fields outside the recipient selector. If the recipient is entitled to a binary object, `plaintext` contains an encrypted object ref and digest, not a base64 megabyte payload by default.

### §4.4 σ block

`sigma_block` contains public-post-reveal authorization evidence:

- `sigma_subject`: vault-retrieved σ_subject or QTSP-sourced equivalent, with digest binding.
- `sigma_lit`: σ_Lit plus Lit assignment id and per-op DCAP quote digest/ref.
- `sigma_g3`: σ_G3 plus `g3_choice` marker (`dcipher` or `drand`) and committee/round ref.
- `sigma_g4`: σ_G4 plus `phase` marker and Phase 1 signature metadata or Phase 2 DCAP quote digest/ref.
- `sigma_conditional`: array of σ_conditional entries with variant tag, stanza index, role tag, and verification mode where applicable.

Normative: σ values may appear in this block after reveal because S2-1 line 44 classifies them as authorization evidence and separates their handling from Shamir shares, decap material, DEK, and plaintext. The block MUST NOT contain Shamir shares, KEM shared secrets, decap transcripts, DEK, or plaintext beyond the recipient block.

Mode 3 `WALLET_EIP1271` entries MUST NOT appear in V2 launch bundles. If encountered in a malformed historical or test artifact, verification returns `ERR_MODE_3_NOT_SHIPPED_AT_V2` per S2-2 lines 1282-1300 and S2-1 error mapping.

### §4.5 Chain proofs

`chain_proofs` contains:

- `commit_tx_hash`
- `commit_block`
- `commit_block_hash`
- `reveal_authorized_tx_hash`
- `reveal_authorized_log_index`
- `reveal_authorized_block`
- `reveal_authorized_block_hash`
- `base_finality_confirmations`
- `finalized_at`
- `challenge_window_expired_at`
- `condition_module`
- `conditionRef`
- `shred_registry_state_at_reveal`

`shred_state` contains `currentShredState(hCommit)`, `proof_shred` when finalized, and timestamps. S2-2 lines 1227-1280 define shred authority, condition axis, mandatory guardrail, triple block, and proof token. The bundle records shred state at reveal so a verifier can see that G4 and the combiner checked the destruction axis.

### §4.6 Issuer and provenance blocks

`issuer_attestation` operationalizes P14. It is always present. When the PDA has no issuer-attested subject-continuity requirement it carries `{ "status": "not_configured" }` and the verifier marks the issuer check skipped. When configured, it contains a signature envelope with `issuer_id`, `issuer_registry_ref`, `issuer_signing_key_id`, `signature_alg`, `signed_payload_digest`, `signature`, `subject_commitment_v3`, `person_key_ref`, validity bounds, revocation ref, and the registry snapshot used for verification. The signature payload is JCS-canonical and binds the issuer claim to the subject-continuity commitment; recipients verify the issuer key against the issuer registry before trusting the claim.

`provenance` operationalizes P15. It is always present. When no per-field provenance was configured it carries `{ "status": "not_configured" }` and the verifier marks the provenance check skipped. When configured, it contains `p15_attestations_root`, `attestor_registry_ref`, registry snapshot refs, and per-field attestation envelopes. Each field envelope contains `field_path`, `field_hash`, `attestor_id`, `attestor_signing_key_id`, `signature_alg`, `signed_payload_digest`, `signature`, Merkle proof, validity bounds, and revocation ref. The verifier recomputes the Merkle root, checks each field signature against the attestor registry, and verifies revocation posture before accepting provenance.

### §4.7 Verification protocol

`@cealis/verify-sdk` exposes:

```ts
verifyArtifactBundle(bundle: RevealArtifactBundle, options?: VerifyOptions): Promise<VerifyArtifactResult>
```

The verifier checks:

1. JCS canonicalization and bundle digest.
2. `h_commit` re-derivation against bundle refs and on-chain event.
3. `RevealAuthorized` event existence, emitter authorization, block hash, finality, and log index.
4. Challenge-window closure.
5. ShredRegistry state.
6. Registry snapshots at authorization block.
7. σ_subject digest and signature/QTSP posture.
8. σ_Lit, σ_G3, σ_G4, and σ_conditional verification.
9. Endpoint attestation four-check evidence.
10. P14 issuer-attestation envelope, registry, signature, and revocation posture.
11. P15 provenance root, per-field Merkle proofs, attestor registry, signatures, and revocation posture.
12. Recipient selector and plaintext field hash consistency.
13. SD refs and disclosed SD artifacts where present.

Return shape is structured pass/fail per check, never a single boolean without diagnostics.

### §4.8 Bundle versioning + canonicalization rule

`bundle_version = "s2-5.1"` for this draft. Additive fields may be added under namespaced objects if JCS canonicalization remains stable and older verifiers ignore unknown keys. Removing or renaming a required key requires a new bundle version.

The canonicalization marker is:

```json
{
  "canonicalization": {
    "format": "JCS",
    "rfc": "RFC8785",
    "hash": "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))"
  }
}
```

Transport headers are not part of the bundle. Webhook wrappers around a bundle carry their own signatures.

## §5 — Partner API surface

### §5.1 Authentication convention

Partner APIs use the §1.2 HMAC plus API-key model. Each partner key has scopes:

- `pda:read`
- `onboarding_link:create`
- `ingestion:create`
- `escrow:read`
- `reveal:read`
- `webhook:manage`
- `vault:read_partner`
- `verification:read`

Bcrypt protects stored API key secrets; request HMAC protects each request in transit and binds method, path, timestamp, nonce, and body digest. Requests older than 300 seconds fail. Nonces cannot repeat within 24 hours for the same key id.

### §5.2 PDA management endpoints

Partners read their PDA; they do not write raw PDA config.

- `GET /v1/partners/me/pdas`
- `GET /v1/partners/me/pdas/{pda_id}`

`PdaInspection` contains:

- `pda_id`, `pda_version`, `pda_root`
- `partner_id`
- schema summary and `schema_digest`
- condition module and trust tier
- operational class
- G3 choice and G4 phase
- ingestion mode
- recipients and schema selectors visible to partner
- conditional-recipient summary where visible
- shred authority and shred condition summary
- retention window
- challenge windows
- SD field mapping summary
- legal flags and jurisdiction summary
- defaults versus partner-selected values
- validation status and class-table refs

S2-4 row 91 line 589 requires the partner-readable inspection surface; partners cannot edit it. Any update request returns `405` with a pointer to Cealis-internal configurator workflow.

### §5.3 Subject onboarding link generation

`POST /v1/partners/me/onboarding-links` creates a token-bearing URL for subject onboarding. The existing orchestrator schema models onboarding links as URL-safe tokens mapping partner plus PDA config, with active/deactivated state.

Request:

- `pda_id`
- `label`
- `expires_at` optional
- `max_uses` optional
- `redirect_url` optional
- `subject_hint` optional encrypted object ref, not raw PII by default

Response:

- `onboarding_link_id`
- `url`
- `token_expires_at`
- `pda_id`
- `pda_version`
- `active`

The token authorizes the browser to fetch public onboarding context. It does not authorize vault access, partner status queries, or reveal delivery.

### §5.4 Status / query endpoints

Partner read endpoints:

- `GET /v1/partners/me/escrows/{h_commit}`
- `GET /v1/partners/me/reveals/{authorizationId}`
- `GET /v1/partners/me/obligations/{obligationId}`
- `GET /v1/partners/me/shreds/{h_commit}`

`EscrowStatus` returns commit state, vault presence, retention, SD status, PDA version, and chain anchor refs. Before reveal, it does not return plaintext or recipient artifacts.

`RevealStatus` returns authorization, finality, challenge, gate collection status, refusal state, combiner delivery state, and artifact bundle digest(s). If reveal has finalized for a recipient the partner is allowed to see, it returns a download ref or bundle digest, not the plaintext inline by default.

`ObligationStatus` is present only for PDAs whose condition module uses obligations. It is not required for testament, archival, evidence, time-lock, or subject-initiated modules.

`ShredStatus` returns requested/authorized/challenge/finalized state, `proof_shred`, vault deletion status, and blocked-future-reveal status.

### §5.5 Error model

Partner API errors use §1.4 taxonomy. Partner-facing messages must be plain-language and scoped. They may say "the PDA does not allow that submitter" or "this reveal has not passed its challenge window." They must not expose internal stack traces, raw chain calldata beyond safe event refs, plaintext, σ, shares, DEK, SD salts, or raw partner secrets.

## §6 — Subject-facing API surface

### §6.1 Authentication

Subjects authenticate with Passkey/WebAuthn Bearer sessions. Session tokens are stored as SHA-256 hashes, expire after 7 days, and are revocable (per the existing `user_sessions` table design).

Endpoints:

- `POST /v1/subjects/webauthn/challenge`
- `POST /v1/subjects/webauthn/verify`
- `POST /v1/subjects/sessions/revoke`

`POST /v1/subjects/webauthn/challenge` and `POST /v1/subjects/webauthn/verify` are challenge/assertion flows and do not use `Idempotency-Key`; retries are governed by challenge expiry, one-time assertion consumption, authenticator replay checks, and rate limits. `POST /v1/subjects/sessions/revoke` requires `SubjectBearer`, `Idempotency-Key`, and the stricter subject-auth rate limit; it returns no token material.

The bearer token grants access only to the subject's own escrows, vault blobs, audit export, retention status, and permitted shred requests.

### §6.2 Self-service endpoints

Subject endpoints:

- `GET /v1/subjects/me/escrows`
- `GET /v1/subjects/me/escrows/{h_commit}`
- `GET /v1/subjects/me/escrows/{h_commit}/vault-blob`
- `GET /v1/subjects/me/audit-log`
- `GET /v1/subjects/me/retention`
- `POST /v1/subjects/me/escrows/{h_commit}/shred-requests`

Subject vault retrieval returns the subject's own encrypted vault blob and metadata only. It never returns subject-readable decrypted data through the vault path. If the subject is also a configured recipient under a subject-self reveal, plaintext access goes through the authorized `RevealArtifactBundle` flow after `RevealAuthorized`, not ordinary vault retrieval. It never returns another partner's data or a cross-partner subject view. `subject_commitment_v3` is per-partner/PDA namespaced, and the API must preserve that unlinkability.

Shred requests are accepted only if the PDA's shredding authority allows subject initiation and the PDA's shred condition can be evaluated. If shredding is disabled for a permanent archival/testament/evidence PDA, the response states that this PDA does not permit subject-initiated shred and returns the configured retention/shred posture.

### §6.3 Ingestion-time pre-σ verifier surface

The subject client retrieves the parse-and-display payload through:

- `GET /v1/onboarding/{token}/pre-sigma-payload`
- `POST /v1/onboarding/{token}/pre-sigma-confirmations`

The payload is the canonical PDA-derived structure parsed by `age-plugin-cealis-v3`, not a UI-only summary. It contains:

- condition module reveal and shred logic summary;
- PDA+ policy surface visible to subject;
- recipients and conditional recipients, with role tags and delivery modes;
- schema digest and payload classification;
- `h_commit` derivation inputs available at this stage;
- σ_subject signing challenge;
- explicit confirmation checklist.

S2-1 lines 1021-1030 and WP §C lines 326-330 require the plugin to parse and display the payload before σ_subject signing and to refuse signing if confirmations are incomplete.

### §6.4 Rate-limiting per-subject

Subject endpoints are rate-limited by session, user id, onboarding token, and IP. WebAuthn challenge endpoints have stricter limits to prevent credential probing. Rate-limit responses do not reveal whether a given subject exists across partners.

## §7 — Webhook event surface

### §7.1 Event taxonomy

Webhooks are generalized lifecycle events, not a hard-coded six-step KYC schedule. S2-2 lines 1830-1832 names the S2-5 consumption events: `RevealAuthorized`, `ShredAuthorized`, `ShredFinalized`, `RefusalSignal`, `ChallengeOpened`, `ChallengeResolved`, and registry deprecation events.

S2-5 event types:

- `commit.finalized`
- `commit.failed`
- `sd.completed`
- `sd.partial_failure`
- `reveal.authorized`
- `challenge.opened`
- `challenge.resolved`
- `reveal.ready_for_gate_signing`
- `reveal.finalized`
- `reveal.failed`
- `g4.refused`
- `shred.authorized`
- `shred.challenge_opened`
- `shred.finalized`
- `halt.triggered`
- `registry.deprecated`
- `vault.retention_expiring`
- `vault.shredded`

Each event has `event_id`, `schema_version`, `event_type`, `created_at`, `partner_id`, `pda_id`, and a `data` object. `data` includes either `h_commit`, `authorizationId`, or both depending on event type.

### §7.2 Authentication

Webhook delivery uses HMAC-SHA256:

- `X-Cealis-Signature: sha256=<hex>`
- `X-Cealis-Timestamp: <unix seconds>`
- `X-Cealis-Event: <event_type>`
- `X-Cealis-Delivery: <event_id>`

Signature input is exactly `utf8(X-Cealis-Timestamp) "." raw_request_body`, where `raw_request_body` is the byte sequence delivered on the wire. Partners reject timestamps outside 300 seconds.

### §7.3 Retry semantics

Delivery retry policy carries forward the V1 interface-closure pattern:

- Retry intervals: 1s, 2s, 4s, 8s, 16s with jitter.
- Max retries: 5.
- Success: HTTP 2xx within 30 seconds.
- Retry: HTTP 5xx, 429, or timeout.
- No retry: HTTP 4xx except 429.
- Dead-letter after exhaustion.

Dead-letter entries are retained as webhook metadata for 90 days per the project retention policy (§0.9, §15).

### §7.4 Idempotent event keys

Event idempotency key:

```
event_key = event_id + ":" + (h_commit || authorizationId)
```

Partners must treat duplicate deliveries with the same event key as the same event. Cealis stores delivery attempts, response status, and final dead-letter state without storing plaintext payloads beyond the event body retention window.

### §7.5 Replay protection

Partners verify timestamp freshness, HMAC signature, and event id. Cealis signs the raw bytes exactly as delivered. Any re-serialization by a proxy invalidates the signature. Partner SDKs should verify before JSON parsing to avoid parser differentials.

Webhook payloads do not carry plaintext reveal content. They carry status, refs, artifact digests, and download refs requiring authenticated pull.

## §8 — Vault access semantics

### §8.1 Subject retrieval of own data

`GET /v1/subjects/me/escrows/{h_commit}/vault-blob` returns the subject's own vault object only after subject authentication and ownership proof. The default format is encrypted vault blob plus metadata:

- `h_commit`
- `vault_ref`
- `content_type`
- `ciphertext_digest`
- `retention_expires_at`
- `shred_state`
- `download_url` short-lived, bound to subject session

The endpoint does not return DEK or shares. It does not bypass reveal. If the subject is also a configured recipient under a subject-self reveal, that delivery path goes through reveal authorization and artifact bundle, not ordinary vault retrieval.

### §8.2 Audit log export

`GET /v1/subjects/me/audit-log` and partner audit export endpoints return append-only audit records scoped to the caller. Vault audit logs are append-only by legal design. Partners see only records for their own PDA/partner namespace. Subjects see only records tied to their own subject account and commitment namespace.

Audit exports contain timestamps, event refs, action types, safe ids, signatures where applicable, and artifact digests. They do not include raw plaintext payloads unless the caller separately downloads an authorized artifact.

### §8.3 Retention queries

`GET /v1/vault/retention/{h_commit}` returns:

- `h_commit`
- `retention_policy_id`
- `retention_expires_at`
- `legal_basis_ref`
- `shred_authority`
- `shred_condition_summary`
- `vault_access_log_retention`
- `webhook_metadata_retention`

Retention follows the retention periods listed in §0.9 and §15.1. The API must show retention state, not imply indefinite safety. Long-retention PDAs may carry re-key obligations under S2-1 §15 and S2-6 ceremonies.

### §8.4 Crypto-shredding API

`POST /v1/subjects/me/escrows/{h_commit}/shred-requests` and `POST /v1/partners/me/escrows/{h_commit}/shred-requests` submit shred requests when PDA authority allows the caller.

Shred authority modes come from S2-2 lines 1231-1239: Subject, Joint, Operator, Timelock, Disabled. Shred condition axis and mandatory `NOT post_challenge_reveal_in_progress` guardrail come from S2-2 lines 1241-1256. Finalized shred lands the triple block from S2-2 lines 1258-1266: G1 refuses future authorization, G4 refuses σ_G4, and S2-5 vault deletes ciphertext after on-chain confirmation.

The prior orchestrator implementation's crypto-shredding service describes a 12-location cascade with critical vault shred and chain deactivate/revoke steps, DB cleanup, Redis purge, guardian notification, webhook, and documented skips. It treats vault shred, identity deactivate, and disclosure revoke as critical/warn steps, followed by session cleanup, notification, and a final audit event.

API success means the shred request was accepted or finalized according to state. It does not claim deletion of partner-held SD outputs or previously delivered reveal bundles.

## §9 — Verification SDKs

### §9.1 `@cealis/verify-sdk` contract

The verification SDK is offline-first. It must not require Cealis availability to verify a completed artifact if the caller has the bundle and chain/registry access.

Primary functions:

```ts
export async function verifyArtifactBundle(
  bundle: RevealArtifactBundle,
  options?: VerifyArtifactOptions
): Promise<VerifyArtifactResult>;

export async function verifySdOutput(
  sd: SdOutput,
  options?: VerifySdOptions
): Promise<VerifySdResult>;

export async function verifyWebhook(
  rawBody: Uint8Array,
  headers: WebhookHeaders,
  secret: Uint8Array,
  now?: Date
): Promise<WebhookVerificationResult>;
```

`VerifyArtifactResult` returns per-check detail:

- `canonicalization`
- `chainProof`
- `pdaRoot`
- `registrySnapshots`
- `endpointAttestation`
- `issuerAttestation`
- `provenance`
- `sigmaSubject`
- `sigmaLit`
- `sigmaG3`
- `sigmaG4`
- `sigmaConditional`
- `shredState`
- `recipientSelector`
- `sdRefs`
- `overall`

Each check has `{ status: "pass" | "fail" | "skipped", code, safe_refs }`.

### §9.2 On-chain verifier contract addresses

`GET /v1/verification/networks` returns a network-indexed manifest:

- chain id;
- ConditionEngine address;
- ShredRegistry address;
- G4RefusalRegistry address;
- registry contract addresses;
- DisclosureRegistry and PLONK verifier addresses for SD;
- deployment block;
- bytecode hashes;
- version labels;
- governance owner refs.

The manifest is convenience data. SDKs must verify addresses against signed release manifests and chain state before treating them as authority.

### §9.3 SDK versioning + version pin discipline

`GET /v1/verification/sdk-versions` returns `SdkVersionManifest` with package names, semver, integrity hashes, lockfile refs, and release signatures. This follows S2-3 §11 lines 680-713: production deployments record both declared version and resolved artifact identity, and dependency upgrades require vector suite reruns.

Stage 3 generated SDK docs live outside this S2-5 spec. This document defines the contract surface and required return shape.

## §10 — Error taxonomy and abort discipline

### §10.1 Layered error model

S2-5 maps HTTP categories to S2-1 cryptographic layers:

- `ATTESTATION` wraps S2-1 endpoint attestation errors.
- `COMBINER` wraps S2-1 §14 and S2-3 §9 errors.
- `GOVERNANCE` wraps S2-2 registry, halt, pause, and refusal errors.
- `VAULT` wraps vault availability, retention, and shred state errors.
- `SCHEMA` wraps S2-4 and S2-7 validation errors.

Cryptographic `ERR_*` codes remain canonical in S2-1. HTTP problem codes are transport classifications and must include the underlying `err_code` where safe.

### §10.2 Confidential-error discipline

No S2-5 error body, log line, metric label, webhook event, dead-letter row, or audit export contains:

- σ raw bytes or partial σ bytes;
- Shamir share bytes;
- decap material;
- DEK or file_key;
- plaintext or partial plaintext;
- SD salts, witnesses, or proof transcripts;
- raw passkey public keys;
- sensitive refusal plaintext for G4 reason codes `0x02` and `0x03`;
- delivery URL secrets or bearer download URLs after expiry.

Allowed safe refs include `authorizationId`, `h_commit`, event id, block number, registry ref, PDA id, partner id, artifact digest, and encrypted diagnostic ref.

### §10.3 Abort discipline

Ingestion abort before plaintext transit: attestation pre-flight fail, authentication fail, PDA mismatch, Mode B reserved, schema mismatch.

Ingestion abort after plaintext transit but before chain anchor: plaintext, DEK, shares, and temporary ciphertext are zeroized/deleted; no commit response is returned. If vault write already completed, cleanup or anchoring retry proceeds under idempotency.

Reveal abort before gate requests: no σ request fires if `RevealAuthorized` is absent, not final, challenge window open, shred finalized, registry pre-authorization deprecated, or caller unauthorized.

Reveal abort after partial gate responses: partial σ and share-bearing materials are zeroized. No combiner partial state persists. Recipient may retry the whole reveal workflow when the error is operationally retryable.

Artifact assembly abort: no partial bundle is published. If one recipient succeeds and another fails, only the successful recipient's per-recipient bundle is finalized; the failed recipient receives a failed status and no shared plaintext.

### §10.4 Halt vs error distinction

G4 refusal is not a generic server error. It is a governance/halt artifact with a bounded reason code. S2-2 lines 1412-1428 define codes `0x01` through `0x0A`: legal compel, Art. 17 erasure, Art. 18 restriction, integrity fail, chain mismatch, plugin deprecated, authority deprecated, DSL deprecated, oracle deprecated, and opt-out active.

For `0x02` and `0x03`, S2-2 lines 1430-1439 require encrypted reason mode by default. The API returns:

```json
{
  "code": "GOVERNANCE.G4_REFUSED",
  "reason_code": "0x03",
  "reason_label": "art_18_restriction",
  "reason_visibility": "encrypted",
  "encrypted_reason_ref": "0x...",
  "retryable": false
}
```

The absence of σ_G4 prevents reveal completion because the G4 share is unavailable. The API does not offer an override.

## §11 — Phase 1 → Phase 2 G4 transition discipline (API view)

### §11.1 What partner sees during transition

Partners see `g4_phase` on every PDA inspection, ingestion response, reveal status, delivery manifest, and artifact bundle. Phase 1 returns registered-binary attestation metadata. Phase 2 returns TEE/DCAP metadata and zkDCAP verifier refs. The endpoint paths do not change.

Partner-ready and legal-effect PDAs must reject new Phase 1 commits. Historical Phase 1 commits remain queryable and verifiable under their original phase metadata.

### §11.2 Existing-commit verification path

Existing commits verify against the phase they committed under. Registry lookups use the authorization block / commit block historical snapshot discipline from S2-1 §11.4 lines 3099-3118 and S2-3 lines 202-209. A Phase 1 commit is not reinterpreted as Phase 2 after cutover.

### §11.3 New-commit binding

After Phase 2 cutover for a PDA class, `/v1/ingestions` rejects new commits whose PDA inspection says `g4_phase = 1` unless the PDA is explicitly dev-scaffold and non-partner-ready. S2-4 CF-05 line 435 rejects Phase 1 for legal-effect or partner-ready PDAs.

### §11.4 API surface for verifying phase

Endpoints exposing phase:

- `GET /v1/partners/me/pdas/{pda_id}`
- `POST /v1/ingestions`
- `GET /v1/ingestions/{h_commit}`
- `GET /v1/reveals/{authorizationId}`
- `GET /v1/reveals/{authorizationId}/delivery-manifest`
- `GET /v1/verification/networks`
- `RevealArtifactBundle.sigma_block.sigma_g4.phase`

SDKs must verify phase against commit_AAD and registry state, not only the HTTP field.

## §12 — Per-PDA-tier API behavior table (NORMATIVE)

Use this table as the API strictness map. It shows how the same PDA is handled at runtime in different operating contexts.

S2-4 defines trust tiers A/B/C at lines 971-999. S2-5 additionally uses partner-facing operational classes for API behavior: `consumer`, `b2b_partner`, `regulated`, and `legal_effect`. A PDA has both a trust tier and an operational class; where they conflict, the stricter API behavior applies.

| API behavior | Consumer | B2B partner | Regulated | Legal-effect |
|---|---|---|---|---|
| G4 phase for new commits | Phase 2 preferred; Phase 1 only if non-partner-ready dev-scaffold | Phase 2 | Phase 2 required | Phase 2 required |
| B2B ingestion | Not applicable | allowed if PDA submitter set permits | mTLS required | mTLS required + legal packet ref |
| Subject auth | Passkey/WebAuthn | Passkey where subject signs | Passkey or QTSP as configured | QTSP when `qes_subject_required` true |
| Pre-flight attestation | mandatory four checks | mandatory four checks | mandatory four checks + audit transcript | mandatory four checks + retained audit transcript |
| Combiner context | audited process memory permitted with warning | recipient server or delegated service | recipient-controlled TEE/HSM or equivalent sandbox | TEE/HSM plus artifact audit packet |
| Webhook payloads | status refs only | lifecycle refs | lifecycle refs + encrypted diagnostics | lifecycle refs + encrypted diagnostics |
| SD cleartext | subject-visible only where configured | partner receives configured fields | ZK-opened cleartext preferred | ZK-opened or counsel-approved |
| Retention floor | PDA-specific | obligation + 3 years default where obligations apply | legal/regulatory floor | legal/counsel floor |
| Shred request auth | subject if allowed | partner/joint/operator if allowed | joint/operator controls often required | counsel-reviewed authority |
| Challenge windows | PDA trust tier controls | PDA trust tier controls | Tier B/C floors enforced | Tier B/C plus Art. 22 safeguards |
| Artifact verification | SDK recommended | SDK required before use | SDK required with stored verification result | SDK required with verification packet |
| Audit export | subject self-service | partner scoped | partner + auditor scoped | partner + auditor + legal packet scoped |

No tier may bypass the universal tripwire. Tiers change attestation strictness, combiner execution context, retention, challenge posture, and audit packaging; they do not create alternate release conditions.

## §13 — Versioning + compatibility

### §13.1 API version bumping discipline

API version bumps are required for:

- removing or renaming a required request/response field;
- changing auth signature input;
- changing webhook signature input;
- changing artifact bundle required keys;
- changing idempotency semantics;
- changing default error category for a failure class;
- changing Mode B from reserved to live.

Additive enum values require a minor schema revision and partner SDK update notice. New webhook event types are additive if partners ignore unknown events.

### §13.2 Backward compatibility windows

Compatibility windows:

- Partner API endpoint deprecation: 180 days.
- Webhook payload shape deprecation: 90 days with dual schema delivery where practical.
- SDK verification manifest deprecation: until all artifacts under that bundle version age out or have a migration verifier.
- Phase 1 G4 historical verification: indefinite for existing commits.

### §13.3 Deprecation timeline + migration

Deprecation notices are served through:

- `GET /v1/verification/sdk-versions`;
- partner dashboard API;
- webhook `registry.deprecated` where relevant;
- signed release manifest;
- S2-6 operational ceremony logs.

Deprecation never changes existing `h_commit` semantics. It can block new commits or pending pre-authorization reveals according to S2-2/S2-3 rules, but already authorized in-flight semantics use the authorization snapshot.

## §14 — Cross-references (per Rule 33 propagation)

### §14.1 Cross-section consistency map

| S2-5 section | Downstream implementation dependency |
|---|---|
| §2 ingestion | Stage 3 G4 service, vault client, chain anchor worker, SD runner |
| §3 reveal delivery | recipient SDK, gate adapter manifest, delivery worker |
| §4 artifact | verify SDK, partner artifact storage, auditor export |
| §5 partner API | orchestrator REST handlers, auth middleware |
| §6 subject API | user app, WebAuthn service, subject vault auth |
| §7 webhooks | webhook worker, retry queue, dead-letter store |
| §8 vault | vault API, retention worker, crypto-shred service |
| §9 verification | SDK package, network manifest, release manifest |
| §10 errors | shared error library, redaction middleware |
| §11 transition | G4 phase registry, cutover runbook |
| §12 tier table | S2-4 validator, partner docs, SDK warnings |

### §14.2 Sibling-spec import map

S2-5 imports but does not redefine:

- S2-1: byte layouts, DEK lifecycle, endpoint attestation, combiner pre-verify, errors.
- S2-2: contracts, events, refusal, shred, Mode 3, EIP-712 domains.
- S2-3: adapters, combiner SDK, transport, hardening, version pins.
- S2-4: PDA shape, class table, tier declaration, partner-readable inspection.
- S2-7: SD output, SD failures, proof verification, Mode B incompatibility.

### §14.3 BP-N candidates surfaced during drafting

BP-N-S2-5-1: Actionable σ-doctrine cleanup. Target files: `docs/specs/cryptography-spec.md`, `docs/specs/custody-integration-spec.md`, `docs/specs/operational-ceremonies-spec.md`, `docs/specs/smart-contracts-spec.md`, `docs/specs/sd-spec-v2.md`, and `docs/specs/wp.md`. Grep terms: `sigma-as-IKM`, `σ-as-IKM`, `direct derivation input`, `σ secrecy`, `sigma secrecy`, `reconstruct file_key`, `MUST NOT leave combiner boundary`, `key material`, and `IKM`. Replacement doctrine: σ is authorization evidence; Shamir shares, decap material, DEK/file_key, and plaintext carry secrecy. Done when no stale σ-as-key-material wording remains outside quoted historical context and S2-1 §14.1.1 no longer contradicts post-reveal artifact `sigma_block` publication.

META-H5 (R12): S2-5 intentionally keeps `RevealArtifactBundle.sigma_block` because σ may appear post-reveal as authorization evidence. The current conflict is in S2-1 §14.1.1's stale σ egress ban, not in S2-5; the S2-1 cleanup owns that fix.

BP-N-S2-5-2: The current orchestrator schema has V1-era `reveals.partialDecryptions` and guardian approval terms (in the prior orchestrator schema). Stage 3 S2-5 implementation should replace or migrate these to V2 gate authorization / artifact delivery state to avoid V1 mental-model leakage.

BP-N-S2-5-3: Partner API auth needs a Stage 3 credential table split between API key identity, request signing secret, webhook signing secret, scopes, rotation, and mTLS subject. Existing schema can support early work but is not enough for full S2-5 scope without migration.

## §15 — Storage discipline + retention

### §15.1 Operative retention periods

S2-5 respects:

- Vault ciphertext: obligation duration plus 3 years.
- Wrapped shares: same as vault.
- Issuer plaintext PII: delete immediately after KYC and onboarding.
- Vault access logs: 12 months rolling.
- Orchestrator delivery logs: 3 years post-delivery.
- Gate/audit approval logs: 3 years post-approval or authorization event.
- Webhook metadata: 90 days rolling.
- On-chain commitments: permanent.

These follow the project retention policy. PDA-specific retention may be stricter or longer where legally required, but API code may not silently shorten below the configured floor.

### §15.2 Vault audit log purge surface

Vault audit logs are append-only during the retention window. Purge after 12 months is a controlled retention function, not ordinary update/delete. API endpoints expose audit export and retention status; they do not expose arbitrary audit-row deletion.

### §15.3 Webhook metadata retention

Webhook delivery metadata is retained for 90 days rolling:

- event id;
- event type;
- partner id;
- delivery URL digest;
- attempt timestamps;
- status code;
- final state;
- dead-letter ref.

Webhook metadata does not store raw reveal plaintext, artifact bundle bodies, raw SD cleartext, or request signing secrets. Dead-letter payload storage uses encrypted object refs when payload retention is necessary for debugging.

## §16 — PII content statement

### §16.1 Plaintext PII flow through API surface

Plaintext PII crosses S2-5 in three legitimate cases:

1. Mode A ingestion upload before encryption inside the G4 boundary.
2. SD cleartext output at onboarding where the PDA explicitly configured selected fields.
3. RevealArtifactBundle plaintext after a valid reveal, filtered by recipient selector.

The first case is transient and must be zeroized after encryption/SD processing. The second is partner-facing data processing at commit time and must be labeled as cleartext, not proof. The third is post-condition release and must be bound to the artifact verification chain.

No other API path may expose plaintext.

### §16.2 Crypto-shredding interaction

Shred is stateful and forward-looking:

- It blocks future reveal authorization through G1.
- It makes G4 refuse σ_G4.
- It deletes vault ciphertext after on-chain confirmation.
- It makes retroactive SD proof generation impossible because plaintext and DEK-derived SD salts are gone.

It does not erase on-chain commitments, partner-held SD outputs, already delivered artifact bundles, or external copies held by recipients. API copy must state this distinction. The prior crypto-shredding service implementation shows the forward-only cascade pattern.

### §16.3 Cross-partner unlinkability of σ_subject

σ_subject stays off-chain in the vault and is included in artifacts only after reveal. Its digest is bound into commit_AAD. WP §C lines 320-324 states σ_subject itself is never anchored on-chain because passkey pubkeys are identity-bearing and on-chain anchoring would create cross-partner linkability. Subject commitments include partner/PDA namespace, and S2-5 APIs must not offer cross-partner subject search or a global subject export.

## App. A — OpenAPI 3.1 reference

```yaml
openapi: 3.1.0
info:
  title: Cealis S2-5 Ingestion and Delivery API
  version: 1.0-draft
servers:
  - url: https://api.cealis.local/v1
security:
  - PartnerHmacKeyId: []
    PartnerHmacTimestamp: []
    PartnerHmacNonce: []
    PartnerHmacSignature: []
  - SubjectBearer: []
paths:
  /g4/attestation:
    get:
      operationId: getG4EndpointAttestation
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
        - SubjectBearer: []
      parameters:
        - $ref: '#/components/parameters/CealisApiVersion'
        - name: pda_id
          in: query
          required: true
          schema: { type: string, format: uuid }
        - name: authorizationIdCandidate
          in: query
          required: true
          schema: { $ref: '#/components/schemas/Hex32' }
        - name: preflight_context_digest
          in: query
          required: true
          schema: { $ref: '#/components/schemas/Hex32' }
        - name: commit_block_number
          in: query
          required: true
          schema: { type: integer, minimum: 0 }
        - name: commit_block_hash
          in: query
          required: true
          schema: { $ref: '#/components/schemas/Hex32' }
      responses:
        '200': { description: attestation object, content: { application/json: { schema: { $ref: '#/components/schemas/G4EndpointAttestationResponse' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /ingestions:
    post:
      operationId: createModeAIngestion
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
        - SubjectBearer: []
      parameters:
        - $ref: '#/components/parameters/IdempotencyKey'
        - $ref: '#/components/parameters/CealisApiVersion'
        - $ref: '#/components/parameters/ClientAttestationDigest'
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/ModeAIngestionRequest' }
          multipart/form-data:
            schema: { $ref: '#/components/schemas/ModeAMultipartIngestionRequest' }
      responses:
        '201': { description: commit created, content: { application/json: { schema: { $ref: '#/components/schemas/ModeAIngestionResponse' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /ingestions/{h_commit}:
    get:
      operationId: getIngestionStatus
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
        - SubjectBearer: []
      parameters:
        - $ref: '#/components/parameters/HCommitPath'
      responses:
        '200': { description: ingestion status, content: { application/json: { schema: { $ref: '#/components/schemas/EscrowStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /reveals/{authorizationId}:
    get:
      operationId: getRevealStatus
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
        - SubjectBearer: []
      parameters:
        - $ref: '#/components/parameters/AuthorizationIdPath'
      responses:
        '200': { description: reveal status, content: { application/json: { schema: { $ref: '#/components/schemas/RevealStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /reveals/{authorizationId}/delivery-manifest:
    get:
      operationId: getCombinerManifest
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
        - SubjectBearer: []
      parameters:
        - $ref: '#/components/parameters/AuthorizationIdPath'
      responses:
        '200': { description: combiner manifest, content: { application/json: { schema: { $ref: '#/components/schemas/CombinerManifest' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /reveals/{authorizationId}/artifact-bundles/{recipient_ref}:
    get:
      operationId: getRevealArtifactBundle
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
        - SubjectBearer: []
      parameters:
        - $ref: '#/components/parameters/AuthorizationIdPath'
        - name: recipient_ref
          in: path
          required: true
          schema: { type: string }
      responses:
        '200': { description: artifact bundle, content: { application/json: { schema: { $ref: '#/components/schemas/RevealArtifactBundle' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /partners/me/pdas:
    get:
      operationId: listPartnerPdas
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
      responses:
        '200':
          description: PDA list
          content:
            application/json:
              schema:
                type: object
                required: [pdas]
                properties:
                  pdas: { type: array, items: { $ref: '#/components/schemas/PdaInspection' } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /partners/me/pdas/{pda_id}:
    get:
      operationId: getPartnerPda
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
      parameters:
        - name: pda_id
          in: path
          required: true
          schema: { type: string, format: uuid }
      responses:
        '200': { description: PDA inspection, content: { application/json: { schema: { $ref: '#/components/schemas/PdaInspection' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /partners/me/onboarding-links:
    post:
      operationId: createOnboardingLink
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
      parameters:
        - $ref: '#/components/parameters/IdempotencyKey'
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/OnboardingLinkRequest' }
      responses:
        '201': { description: onboarding link, content: { application/json: { schema: { $ref: '#/components/schemas/OnboardingLinkResponse' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /partners/me/escrows/{h_commit}:
    get:
      operationId: getPartnerEscrowStatus
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
      parameters: [{ $ref: '#/components/parameters/HCommitPath' }]
      responses:
        '200': { description: escrow status, content: { application/json: { schema: { $ref: '#/components/schemas/EscrowStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /partners/me/escrows/{h_commit}/shred-requests:
    post:
      operationId: createPartnerShredRequest
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
      parameters:
        - $ref: '#/components/parameters/HCommitPath'
        - $ref: '#/components/parameters/IdempotencyKey'
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/ShredRequest' }
      responses:
        '202': { description: shred accepted, content: { application/json: { schema: { $ref: '#/components/schemas/ShredStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /partners/me/reveals/{authorizationId}:
    get:
      operationId: getPartnerRevealStatus
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
      parameters: [{ $ref: '#/components/parameters/AuthorizationIdPath' }]
      responses:
        '200': { description: reveal status, content: { application/json: { schema: { $ref: '#/components/schemas/RevealStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /partners/me/obligations/{obligationId}:
    get:
      operationId: getPartnerObligationStatus
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
      parameters:
        - $ref: '#/components/parameters/ObligationIdPath'
      responses:
        '200': { description: obligation status, content: { application/json: { schema: { $ref: '#/components/schemas/ObligationStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /partners/me/shreds/{h_commit}:
    get:
      operationId: getPartnerShredStatus
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
      parameters: [{ $ref: '#/components/parameters/HCommitPath' }]
      responses:
        '200': { description: shred status, content: { application/json: { schema: { $ref: '#/components/schemas/ShredStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/webauthn/challenge:
    post:
      operationId: createSubjectWebAuthnChallenge
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [purpose]
              properties:
                purpose: { type: string, enum: [login, sigma_subject, shred_request] }
      responses:
        '200': { description: challenge, content: { application/json: { schema: { type: object, required: [challenge], properties: { challenge: { type: string } } } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/webauthn/verify:
    post:
      operationId: verifySubjectWebAuthn
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema: { type: object, required: [challenge_id, assertion], properties: { challenge_id: { type: string }, assertion: { type: object } } }
      responses:
        '200': { description: session, content: { application/json: { schema: { $ref: '#/components/schemas/SubjectSession' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/sessions/revoke:
    post:
      operationId: revokeSubjectSession
      security: [{ SubjectBearer: [] }]
      parameters:
        - $ref: '#/components/parameters/IdempotencyKey'
      requestBody:
        required: false
        content:
          application/json:
            schema: { $ref: '#/components/schemas/SubjectSessionRevokeRequest' }
      responses:
        '200': { description: subject session revoked, content: { application/json: { schema: { $ref: '#/components/schemas/SubjectSessionRevokeResponse' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/me/escrows:
    get:
      operationId: listSubjectEscrows
      security: [{ SubjectBearer: [] }]
      responses:
        '200': { description: subject escrows, content: { application/json: { schema: { $ref: '#/components/schemas/SubjectEscrowList' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/me/escrows/{h_commit}:
    get:
      operationId: getSubjectEscrowStatus
      security: [{ SubjectBearer: [] }]
      parameters:
        - $ref: '#/components/parameters/HCommitPath'
      responses:
        '200': { description: subject escrow status, content: { application/json: { schema: { $ref: '#/components/schemas/EscrowStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/me/escrows/{h_commit}/vault-blob:
    get:
      operationId: getSubjectVaultBlob
      security: [{ SubjectBearer: [] }]
      parameters: [{ $ref: '#/components/parameters/HCommitPath' }]
      responses:
        '200': { description: vault blob, content: { application/json: { schema: { $ref: '#/components/schemas/VaultBlobResponse' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/me/audit-log:
    get:
      operationId: exportSubjectAuditLog
      security: [{ SubjectBearer: [] }]
      responses:
        '200': { description: audit log, content: { application/json: { schema: { $ref: '#/components/schemas/AuditLogExport' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/me/retention:
    get:
      operationId: getSubjectRetention
      security: [{ SubjectBearer: [] }]
      responses:
        '200': { description: retention, content: { application/json: { schema: { type: object, required: [items], properties: { items: { type: array, items: { $ref: '#/components/schemas/RetentionStatus' } } } } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /subjects/me/escrows/{h_commit}/shred-requests:
    post:
      operationId: createSubjectShredRequest
      security: [{ SubjectBearer: [] }]
      parameters:
        - $ref: '#/components/parameters/HCommitPath'
        - $ref: '#/components/parameters/IdempotencyKey'
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/ShredRequest' }
      responses:
        '202': { description: shred accepted, content: { application/json: { schema: { $ref: '#/components/schemas/ShredStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /onboarding/{token}/pre-sigma-payload:
    get:
      operationId: getPreSigmaPayload
      security: []
      parameters:
        - name: token
          in: path
          required: true
          schema: { type: string }
      responses:
        '200': { description: pre sigma payload, content: { application/json: { schema: { $ref: '#/components/schemas/PreSigmaPayload' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /onboarding/{token}/pre-sigma-confirmations:
    post:
      operationId: submitPreSigmaConfirmations
      security: []
      parameters:
        - name: token
          in: path
          required: true
          schema: { type: string }
        - $ref: '#/components/parameters/IdempotencyKey'
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/PreSigmaConfirmationRequest' }
      responses:
        '200': { description: accepted, content: { application/json: { schema: { type: object, required: [pre_sigma_session_id], properties: { pre_sigma_session_id: { type: string } } } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /vault/retention/{h_commit}:
    get:
      operationId: getVaultRetention
      security:
        - PartnerHmacKeyId: []
          PartnerHmacTimestamp: []
          PartnerHmacNonce: []
          PartnerHmacSignature: []
        - SubjectBearer: []
      parameters: [{ $ref: '#/components/parameters/HCommitPath' }]
      responses:
        '200': { description: retention status, content: { application/json: { schema: { $ref: '#/components/schemas/RetentionStatus' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /verify/artifact-bundles:
    post:
      operationId: verifyArtifactBundle
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/VerifyArtifactRequest' }
      responses:
        '200': { description: verification result, content: { application/json: { schema: { $ref: '#/components/schemas/VerifyArtifactResponse' } } } }
        default: { $ref: '#/components/responses/ProblemResponse' }
  /verification/networks:
    get:
      operationId: getVerificationNetworks
      security: []
      responses:
        '200': { description: network manifest, content: { application/json: { schema: { type: object, required: [networks], properties: { networks: { type: array, items: { $ref: '#/components/schemas/NetworkVerificationManifest' } } } } } } }
  /verification/sdk-versions:
    get:
      operationId: getSdkVersions
      security: []
      responses:
        '200': { description: SDK versions, content: { application/json: { schema: { $ref: '#/components/schemas/SdkVersionManifest' } } } }
components:
  securitySchemes:
    PartnerHmacKeyId:
      type: apiKey
      in: header
      name: X-Cealis-Key-Id
      description: Opaque partner key id used for signing-secret lookup and scope enforcement.
    PartnerHmacTimestamp:
      type: apiKey
      in: header
      name: X-Cealis-Timestamp
      description: Unix seconds bound into canonical_request; requests older than 300 seconds fail.
    PartnerHmacNonce:
      type: apiKey
      in: header
      name: X-Cealis-Nonce
      description: 128-bit base64url nonce bound into canonical_request; no repeats within 24h per key id.
    PartnerHmacSignature:
      type: apiKey
      in: header
      name: X-Cealis-Signature
      description: sha256=<hex HMAC-SHA256(signing_secret, canonical_request)>.
    SubjectBearer:
      type: http
      scheme: bearer
  parameters:
    IdempotencyKey:
      name: Idempotency-Key
      in: header
      required: true
      schema: { type: string, minLength: 8, maxLength: 200 }
    CealisApiVersion:
      name: Cealis-Api-Version
      in: header
      required: false
      schema: { type: string }
    ClientAttestationDigest:
      name: X-Cealis-Client-Attestation-Digest
      in: header
      required: true
      schema: { $ref: '#/components/schemas/Hex32' }
    HCommitPath:
      name: h_commit
      in: path
      required: true
      schema: { $ref: '#/components/schemas/Hex32' }
    AuthorizationIdPath:
      name: authorizationId
      in: path
      required: true
      schema: { $ref: '#/components/schemas/Hex32' }
    ObligationIdPath:
      name: obligationId
      in: path
      required: true
      schema: { $ref: '#/components/schemas/Hex32' }
  responses:
    ProblemResponse:
      description: problem
      content:
        application/problem+json:
          schema: { $ref: '#/components/schemas/Problem' }
  schemas:
    Hex32:
      type: string
      pattern: '^0x[a-fA-F0-9]{64}$'
    Hex:
      type: string
      pattern: '^0x[a-fA-F0-9]*$'
    EvmAddress:
      type: string
      pattern: '^0x[a-fA-F0-9]{40}$'
    Problem:
      type: object
      required: [type, title, status, code, category, correlation_id, retryable]
      properties:
        type: { type: string, format: uri }
        title: { type: string }
        status: { type: integer }
        code: { type: string }
        category: { type: string, enum: [REQUEST, AUTH, ATTESTATION, VAULT, CHAIN, COMBINER, SCHEMA, IDEMPOTENCY, RATE_LIMIT, TRANSPORT, GOVERNANCE, RETRY_EXHAUSTED] }
        detail: { type: string }
        correlation_id: { type: string }
        retryable: { type: boolean }
        safe_refs: { type: object, additionalProperties: true }
    PreflightCommitContext:
      type: object
      required: [authorizationIdCandidate, pda_id, pda_version, partner_id, schema_digest, payload_digest, payload_canonicalization, pda_root, g3_choice, g4_phase, commit_block_number, commit_block_hash]
      properties:
        authorizationIdCandidate: { $ref: '#/components/schemas/Hex32' }
        pda_id: { type: string, format: uuid }
        pda_version: { type: string }
        partner_id: { type: string, format: uuid }
        schema_digest: { $ref: '#/components/schemas/Hex32' }
        payload_digest: { $ref: '#/components/schemas/Hex32' }
        payload_canonicalization: { type: string, enum: [jcs_json, raw_binary, multipart_file_part] }
        pda_root: { $ref: '#/components/schemas/Hex32' }
        g3_choice: { type: string, enum: [dcipher, drand] }
        g4_phase: { type: integer, enum: [1, 2] }
        commit_block_number: { type: integer, minimum: 0 }
        commit_block_hash: { $ref: '#/components/schemas/Hex32' }
        block_source: { type: string }
    RegistrySnapshotRef:
      type: object
      required: [registry_name, chain_id, registry_address, checked_block, checked_block_hash, entry_digest]
      properties:
        registry_name: { type: string }
        chain_id: { type: integer }
        registry_address: { $ref: '#/components/schemas/EvmAddress' }
        checked_block: { type: integer, minimum: 0 }
        checked_block_hash: { $ref: '#/components/schemas/Hex32' }
        lookup_key: { type: string }
        entry_digest: { $ref: '#/components/schemas/Hex32' }
        proof_ref: { type: string }
    VerificationCheckResult:
      type: object
      required: [status, checked_block, checked_block_hash]
      properties:
        status: { type: string, enum: [pass, fail] }
        checked_block: { type: integer, minimum: 0 }
        checked_block_hash: { $ref: '#/components/schemas/Hex32' }
        code: { type: string }
        safe_refs: { type: object, additionalProperties: true }
    AttestationVerificationChecks:
      type: object
      required: [lit_assignment, lit_dcap, g3_pubkey, g4_authority]
      properties:
        lit_assignment: { $ref: '#/components/schemas/VerificationCheckResult' }
        lit_dcap: { $ref: '#/components/schemas/VerificationCheckResult' }
        g3_pubkey: { $ref: '#/components/schemas/VerificationCheckResult' }
        g4_authority: { $ref: '#/components/schemas/VerificationCheckResult' }
    LitAssignmentProof:
      type: object
      required: [authorizationId, assignment_digest, assigned_operator_id, registry_ref]
      properties:
        authorizationId: { $ref: '#/components/schemas/Hex32' }
        assignment_digest: { $ref: '#/components/schemas/Hex32' }
        assigned_operator_id: { type: string }
        registry_ref: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        assignment_record_ref: { type: string }
    LitDcapProof:
      type: object
      required: [quote_digest, bound_authorizationId, bound_preflight_context_digest, bound_block_hash, tee_vendor_family, measurement, registry_ref]
      properties:
        quote_digest: { $ref: '#/components/schemas/Hex32' }
        bound_authorizationId: { $ref: '#/components/schemas/Hex32' }
        bound_preflight_context_digest: { $ref: '#/components/schemas/Hex32' }
        bound_block_hash: { $ref: '#/components/schemas/Hex32' }
        tee_vendor_family: { type: string }
        measurement: { type: string }
        user_data_binding_digest: { $ref: '#/components/schemas/Hex32' }
        registry_ref: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        quote_ref: { type: string }
    G3PubkeyEvidence:
      type: object
      required: [network, pubkey_digest, registry_ref]
      properties:
        network: { type: string, enum: [dcipher, drand] }
        pubkey_digest: { $ref: '#/components/schemas/Hex32' }
        registry_ref: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        committee_id: { type: string }
        pubkey_ref: { type: string }
    G4AuthorityEvidence:
      type: object
      required: [phase, registry_ref]
      properties:
        phase: { type: integer, enum: [1, 2] }
        registry_ref: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        phase1:
          type: object
          required: [binary_hash, effective_block, ed25519_signature, phase_trust_statement]
          properties:
            binary_hash: { $ref: '#/components/schemas/Hex32' }
            effective_block: { type: integer, minimum: 0 }
            ed25519_signature: { type: string }
            phase_trust_statement: { type: string, const: phase_1_registered_binary }
        phase2:
          type: object
          required: [quote_digest, measurement, user_data_binding_digest, zkdcap_verifier_ref]
          properties:
            quote_digest: { $ref: '#/components/schemas/Hex32' }
            measurement: { type: string }
            user_data_binding_digest: { $ref: '#/components/schemas/Hex32' }
            zkdcap_verifier_ref: { type: string }
    AttestationPreflight:
      type: object
      required: [digest, authorizationIdCandidate, preflight_context_digest, commit_block_number, commit_block_hash, registry_refs, lit_assignment, lit_dcap, g3_pubkey, g4_authority, verification_checks]
      properties:
        digest: { $ref: '#/components/schemas/Hex32' }
        authorizationIdCandidate: { $ref: '#/components/schemas/Hex32' }
        preflight_context_digest: { $ref: '#/components/schemas/Hex32' }
        commit_block_number: { type: integer, minimum: 0 }
        commit_block_hash: { $ref: '#/components/schemas/Hex32' }
        registry_refs: { type: array, minItems: 3, items: { $ref: '#/components/schemas/RegistrySnapshotRef' } }
        lit_assignment: { $ref: '#/components/schemas/LitAssignmentProof' }
        lit_dcap: { $ref: '#/components/schemas/LitDcapProof' }
        g3_pubkey: { $ref: '#/components/schemas/G3PubkeyEvidence' }
        g4_authority: { $ref: '#/components/schemas/G4AuthorityEvidence' }
        verification_checks: { $ref: '#/components/schemas/AttestationVerificationChecks' }
    G4EndpointAttestationResponse:
      type: object
      required: [phase, pda_id, authorizationIdCandidate, preflight_context_digest, commit_block_number, commit_block_hash, attestation_digest, verification_checks, attestation_preflight]
      properties:
        phase: { type: integer, enum: [1, 2] }
        pda_id: { type: string, format: uuid }
        authorizationIdCandidate: { $ref: '#/components/schemas/Hex32' }
        preflight_context_digest: { $ref: '#/components/schemas/Hex32' }
        commit_block_number: { type: integer, minimum: 0 }
        commit_block_hash: { $ref: '#/components/schemas/Hex32' }
        attestation_digest: { $ref: '#/components/schemas/Hex32' }
        phase1: { type: object, additionalProperties: true }
        phase2: { type: object, additionalProperties: true }
        verification_checks: { $ref: '#/components/schemas/AttestationVerificationChecks' }
        attestation_preflight: { $ref: '#/components/schemas/AttestationPreflight' }
    ModeAIngestionMetadata:
      type: object
      required: [pda_id, pda_version, partner_id, authorizationIdCandidate, preflight_commit_context, preflight_context_digest, schema_digest, payload_classification, attestation_preflight, client_attestation_digest]
      properties:
        pda_id: { type: string, format: uuid }
        pda_version: { type: string }
        partner_id: { type: string, format: uuid }
        authorizationIdCandidate: { $ref: '#/components/schemas/Hex32' }
        preflight_commit_context: { $ref: '#/components/schemas/PreflightCommitContext' }
        preflight_context_digest: { $ref: '#/components/schemas/Hex32' }
        subject_commitment_inputs: { type: object, additionalProperties: true }
        sigma_subject: { $ref: '#/components/schemas/Hex' }
        pre_sigma_session_id: { type: string }
        schema_digest: { $ref: '#/components/schemas/Hex32' }
        payload_classification: { type: object, additionalProperties: true }
        attestation_preflight: { $ref: '#/components/schemas/AttestationPreflight' }
        client_attestation_digest:
          allOf: [{ $ref: '#/components/schemas/Hex32' }]
          description: Must equal X-Cealis-Client-Attestation-Digest and attestation_preflight.digest.
        conditional_recipient_confirmations: { type: array, items: { type: string } }
    ModeAIngestionRequest:
      type: object
      required: [pda_id, pda_version, partner_id, authorizationIdCandidate, preflight_commit_context, preflight_context_digest, schema_digest, payload_classification, plaintext_payload, attestation_preflight, client_attestation_digest]
      properties:
        pda_id: { type: string, format: uuid }
        pda_version: { type: string }
        partner_id: { type: string, format: uuid }
        authorizationIdCandidate: { $ref: '#/components/schemas/Hex32' }
        preflight_commit_context: { $ref: '#/components/schemas/PreflightCommitContext' }
        preflight_context_digest: { $ref: '#/components/schemas/Hex32' }
        subject_commitment_inputs: { type: object, additionalProperties: true }
        sigma_subject: { $ref: '#/components/schemas/Hex' }
        pre_sigma_session_id: { type: string }
        schema_digest: { $ref: '#/components/schemas/Hex32' }
        payload_classification: { type: object, additionalProperties: true }
        plaintext_payload: {}
        attestation_preflight: { $ref: '#/components/schemas/AttestationPreflight' }
        client_attestation_digest:
          allOf: [{ $ref: '#/components/schemas/Hex32' }]
          description: Must equal X-Cealis-Client-Attestation-Digest and attestation_preflight.digest.
        conditional_recipient_confirmations: { type: array, items: { type: string } }
    ModeAMultipartIngestionRequest:
      type: object
      required: [metadata, plaintext_payload]
      properties:
        metadata: { $ref: '#/components/schemas/ModeAIngestionMetadata' }
        plaintext_payload: { type: string, format: binary }
    ModeAIngestionResponse:
      type: object
      required: [api_version, commit_version, ingestion_id, authorizationId, h_commit, pda_id, pda_version, partner_id, vault_ref, status]
      properties:
        api_version: { type: string }
        commit_version: { type: string, const: '0x0302' }
        ingestion_id: { type: string }
        authorizationId: { $ref: '#/components/schemas/Hex32' }
        h_commit: { $ref: '#/components/schemas/Hex32' }
        pda_id: { type: string, format: uuid }
        pda_version: { type: string }
        partner_id: { type: string, format: uuid }
        vault_ref: { type: string }
        commit_tx_hash: { type: string }
        commit_block: { type: integer }
        endpoint_attestation_digest: { $ref: '#/components/schemas/Hex32' }
        g3_choice: { type: string, enum: [dcipher, drand] }
        g4_phase: { type: integer, enum: [1, 2] }
        retention_expires_at: { type: string, format: date-time }
        sd_output: { $ref: '#/components/schemas/SdOutput' }
        status: { type: string, enum: [committed, pending_chain_anchor, failed] }
    SdOutput:
      type: object
      required: [status]
      properties:
        status: { type: string, enum: [complete, failed, partial_failure, skipped, not_configured] }
        authorizationId: { $ref: '#/components/schemas/Hex32' }
        h_commit: { $ref: '#/components/schemas/Hex32' }
        sdMerkleRoot: { type: string }
        cleartext: { type: array, items: { type: object, additionalProperties: true } }
        claims: { type: array, items: { type: object, additionalProperties: true } }
        failures: { type: array, items: { type: object, additionalProperties: true } }
    CombinerManifest:
      type: object
      required: [authorizationId, h_commit, authorization_block, block_hash, pda_id, g3_choice, g4_phase, gate_endpoints, registry_snapshot_refs, recipient_policy, combiner_execution_context, delegation_allowed, recipient_control_requirement, tee_hsm_required, risk_statement_required, policy_evidence_refs]
      properties:
        authorizationId: { $ref: '#/components/schemas/Hex32' }
        h_commit: { $ref: '#/components/schemas/Hex32' }
        authorization_block: { type: integer }
        block_hash: { $ref: '#/components/schemas/Hex32' }
        pda_id: { type: string, format: uuid }
        g3_choice: { type: string, enum: [dcipher, drand] }
        g4_phase: { type: integer, enum: [1, 2] }
        gate_endpoints: { type: object, additionalProperties: true }
        registry_snapshot_refs: { type: object, additionalProperties: true }
        recipient_policy: { type: object, additionalProperties: true }
        combiner_execution_context: { type: string, enum: [audited_process_memory, recipient_controlled_tee, recipient_controlled_hsm, delegated_non_custodial_service, prohibited] }
        delegation_allowed: { type: boolean }
        recipient_control_requirement: { type: string, enum: [recipient_local, recipient_controlled_service, delegated_allowed, delegation_prohibited] }
        tee_hsm_required: { type: boolean }
        risk_statement_required: { type: boolean }
        policy_evidence_refs: { type: array, items: { $ref: '#/components/schemas/PolicyEvidenceRef' } }
    RevealArtifactBundle:
      type: object
      required: [bundle_version, canonicalization, authorization, pda, recipient, plaintext, issuer_attestation, provenance, sigma_block, chain_proofs, registry_snapshots, shred_state, sd_refs, verification, pii_statement]
      properties:
        bundle_version: { type: string }
        canonicalization: { $ref: '#/components/schemas/Canonicalization' }
        authorization: { $ref: '#/components/schemas/ArtifactAuthorization' }
        pda: { $ref: '#/components/schemas/ArtifactPda' }
        recipient: { $ref: '#/components/schemas/ArtifactRecipient' }
        plaintext: { $ref: '#/components/schemas/ArtifactPlaintext' }
        issuer_attestation: { $ref: '#/components/schemas/IssuerAttestationBlock' }
        provenance: { $ref: '#/components/schemas/ProvenanceBlock' }
        sigma_block: { $ref: '#/components/schemas/SigmaBlock' }
        chain_proofs: { $ref: '#/components/schemas/ChainProofs' }
        registry_snapshots: { $ref: '#/components/schemas/RegistrySnapshots' }
        shred_state: { $ref: '#/components/schemas/ArtifactShredState' }
        sd_refs: { $ref: '#/components/schemas/ArtifactSdRefs' }
        verification: { $ref: '#/components/schemas/ArtifactVerification' }
        pii_statement: { $ref: '#/components/schemas/PiiStatement' }
    PdaInspection:
      type: object
      required: [pda_id, pda_version, pda_root, partner_id, ingestion_mode, g3_choice, g4_phase, trust_tier, operational_class]
      properties:
        pda_id: { type: string, format: uuid }
        pda_version: { type: string }
        pda_root: { $ref: '#/components/schemas/Hex32' }
        partner_id: { type: string, format: uuid }
        schema_digest: { $ref: '#/components/schemas/Hex32' }
        ingestion_mode: { type: string, enum: [mode_a, mode_b_reserved] }
        g3_choice: { type: string, enum: [dcipher, drand] }
        g4_phase: { type: integer, enum: [1, 2] }
        trust_tier: { type: string, enum: [tier_a, tier_b, tier_c] }
        operational_class: { type: string, enum: [consumer, b2b_partner, regulated, legal_effect] }
        recipients: { type: array, items: { type: object, additionalProperties: true } }
        retention: { $ref: '#/components/schemas/RetentionStatus' }
    OnboardingLinkRequest:
      type: object
      required: [pda_id, label]
      properties:
        pda_id: { type: string, format: uuid }
        label: { type: string }
        expires_at: { type: string, format: date-time }
        max_uses: { type: integer, minimum: 1 }
        redirect_url: { type: string, format: uri }
    OnboardingLinkResponse:
      type: object
      required: [onboarding_link_id, url, pda_id, active]
      properties:
        onboarding_link_id: { type: string, format: uuid }
        url: { type: string, format: uri }
        token_expires_at: { type: string, format: date-time }
        pda_id: { type: string, format: uuid }
        pda_version: { type: string }
        active: { type: boolean }
    EscrowStatus:
      type: object
      required: [h_commit, status, pda_id, g4_phase]
      properties:
        h_commit: { $ref: '#/components/schemas/Hex32' }
        status: { type: string }
        pda_id: { type: string, format: uuid }
        g4_phase: { type: integer, enum: [1, 2] }
        vault_ref: { type: string }
        retention_expires_at: { type: string, format: date-time }
        sd_status: { type: string }
    RevealStatus:
      type: object
      required: [authorizationId, h_commit, status, g4_phase]
      properties:
        authorizationId: { $ref: '#/components/schemas/Hex32' }
        h_commit: { $ref: '#/components/schemas/Hex32' }
        status: { type: string }
        g4_phase: { type: integer, enum: [1, 2] }
        challenge_window_expired_at: { type: string, format: date-time }
        refusal: { type: object, additionalProperties: true }
        sigma_block: { $ref: '#/components/schemas/SigmaBlock' }
        artifact_bundles: { type: array, items: { type: object, additionalProperties: true } }
    ObligationStatus:
      type: object
      required: [obligationId, status, pda_id]
      properties:
        obligationId: { $ref: '#/components/schemas/Hex32' }
        authorizationId: { $ref: '#/components/schemas/Hex32' }
        h_commit: { $ref: '#/components/schemas/Hex32' }
        pda_id: { type: string, format: uuid }
        status: { type: string, enum: [pending, active, paid, cured, default_observed, challenged, finalized, cancelled] }
        due_at: { type: string, format: date-time }
        conditionRef: { $ref: '#/components/schemas/Hex32' }
    ShredStatus:
      type: object
      required: [h_commit, status]
      properties:
        h_commit: { $ref: '#/components/schemas/Hex32' }
        status: { type: string }
        proof_shred: { $ref: '#/components/schemas/Hex32' }
        vault_deleted: { type: boolean }
    SubjectSession:
      type: object
      required: [access_token, expires_at]
      properties:
        access_token: { type: string }
        expires_at: { type: string, format: date-time }
    SubjectSessionRevokeRequest:
      type: object
      properties:
        scope: { type: string, enum: [current_session, all_sessions], default: current_session }
        reason: { type: string, enum: [user_logout, suspected_compromise, rotation] }
    SubjectSessionRevokeResponse:
      type: object
      required: [revoked, scope, revoked_at]
      properties:
        revoked: { type: boolean, const: true }
        scope: { type: string, enum: [current_session, all_sessions] }
        revoked_at: { type: string, format: date-time }
    SubjectEscrowList:
      type: object
      required: [escrows]
      properties:
        escrows: { type: array, items: { $ref: '#/components/schemas/EscrowStatus' } }
    VaultBlobResponse:
      type: object
      required: [h_commit, vault_ref, ciphertext_digest, retention_expires_at, download_url]
      properties:
        h_commit: { $ref: '#/components/schemas/Hex32' }
        vault_ref: { type: string }
        content_type: { type: string }
        ciphertext_digest: { $ref: '#/components/schemas/Hex32' }
        retention_expires_at: { type: string, format: date-time }
        download_url: { type: string, format: uri }
    AuditLogExport:
      type: object
      required: [generated_at, items]
      properties:
        generated_at: { type: string, format: date-time }
        items: { type: array, items: { type: object, additionalProperties: true } }
    RetentionStatus:
      type: object
      required: [h_commit, retention_expires_at]
      properties:
        h_commit: { $ref: '#/components/schemas/Hex32' }
        retention_policy_id: { type: string }
        retention_expires_at: { type: string, format: date-time }
        shred_authority: { $ref: '#/components/schemas/ShredAuthorityMode' }
        shred_condition_summary: { type: string }
    ShredAuthorityMode:
      type: string
      enum: [subject, joint, operator, timelock, disabled]
    ShredRequest:
      type: object
      required: [reason]
      properties:
        reason: { type: string, enum: [art_17_erasure, retention_expired, subject_request, partner_request, operator_request] }
        evidence_ref: { type: string }
    PreSigmaPayload:
      type: object
      required: [pda_id, schema_digest, condition_summary, shred_logic_summary, subject_visible_policy, recipients, conditional_recipients, payload_classification, h_commit_derivation_inputs, signing_challenge, confirmation_checklist, canonical_payload_digest]
      properties:
        pda_id: { type: string, format: uuid }
        schema_digest: { $ref: '#/components/schemas/Hex32' }
        condition_summary: { type: object, additionalProperties: true }
        shred_logic_summary: { type: object, additionalProperties: true }
        subject_visible_policy: { type: object, additionalProperties: true }
        recipients: { type: array, items: { type: object, additionalProperties: true } }
        conditional_recipients: { type: array, items: { type: object, additionalProperties: true } }
        payload_classification: { type: object, additionalProperties: true }
        h_commit_derivation_inputs: { type: object, additionalProperties: true }
        signing_challenge: { $ref: '#/components/schemas/Hex32' }
        confirmation_checklist: { type: array, items: { type: string } }
        canonical_payload_digest: { $ref: '#/components/schemas/Hex32' }
        display_items: { type: array, items: { type: object, additionalProperties: true } }
    PreSigmaConfirmationRequest:
      type: object
      required: [confirmed_items, canonical_payload_digest, signing_challenge]
      properties:
        confirmed_items: { type: array, items: { type: string } }
        canonical_payload_digest: { $ref: '#/components/schemas/Hex32' }
        signing_challenge: { $ref: '#/components/schemas/Hex32' }
    WebhookEvent:
      type: object
      required: [event_id, schema_version, event_type, created_at, partner_id, pda_id, data]
      properties:
        event_id: { type: string }
        schema_version: { type: string }
        event_type: { $ref: '#/components/schemas/WebhookEventType' }
        created_at: { type: string, format: date-time }
        partner_id: { type: string, format: uuid }
        pda_id: { type: string, format: uuid }
        data:
          oneOf:
            - $ref: '#/components/schemas/CommitWebhookData'
            - $ref: '#/components/schemas/SdWebhookData'
            - $ref: '#/components/schemas/RevealWebhookData'
            - $ref: '#/components/schemas/ChallengeWebhookData'
            - $ref: '#/components/schemas/G4RefusalWebhookData'
            - $ref: '#/components/schemas/ShredWebhookData'
            - $ref: '#/components/schemas/HaltWebhookData'
            - $ref: '#/components/schemas/RegistryWebhookData'
            - $ref: '#/components/schemas/VaultWebhookData'
    VerifyArtifactRequest:
      type: object
      required: [bundle]
      properties:
        bundle: { $ref: '#/components/schemas/RevealArtifactBundle' }
        options: { type: object, additionalProperties: true }
    VerifyArtifactResponse:
      type: object
      required: [overall, checks]
      properties:
        overall: { type: string, enum: [pass, fail] }
        checks: { type: object, additionalProperties: true }
    NetworkVerificationManifest:
      type: object
      required: [chain_id, contracts]
      properties:
        chain_id: { type: integer }
        contracts: { type: object, additionalProperties: true }
        deployment_block: { type: integer }
        bytecode_hashes: { type: object, additionalProperties: true }
    SdkVersionManifest:
      type: object
      required: [generated_at, packages]
      properties:
        generated_at: { type: string, format: date-time }
        packages: { type: array, items: { $ref: '#/components/schemas/SdkPackageVersion' } }
    SdkPackageVersion:
      type: object
      required: [name, semver, integrity_hash, lockfile_ref, release_signature, resolved_artifact_identity]
      properties:
        name: { type: string }
        semver: { type: string }
        integrity_hash: { $ref: '#/components/schemas/Hex32' }
        lockfile_ref: { type: string }
        release_signature: { type: string }
        resolved_artifact_identity: { type: string }
    PolicyEvidenceRef:
      type: object
      required: [policy_ref, digest]
      properties:
        policy_ref: { type: string }
        digest: { $ref: '#/components/schemas/Hex32' }
    Canonicalization:
      type: object
      required: [format, rfc, hash]
      properties:
        format: { type: string, const: JCS }
        rfc: { type: string, const: RFC8785 }
        hash: { type: string, const: keccak256(utf8(jcs(reveal_artifact_bundle_json_object))) }
    ArtifactAuthorization:
      type: object
      required: [authorizationId, h_commit, commit_version, authorization_block, authorization_block_hash, authorization_timestamp, conditionRef, challenge_window_seconds, challenge_window_expired_at, finalized_at]
      properties:
        authorizationId: { $ref: '#/components/schemas/Hex32' }
        h_commit: { $ref: '#/components/schemas/Hex32' }
        commit_version: { type: string, const: '0x0302' }
        authorization_block: { type: integer }
        authorization_block_hash: { $ref: '#/components/schemas/Hex32' }
        authorization_timestamp: { type: string, format: date-time }
        conditionRef: { $ref: '#/components/schemas/Hex32' }
        challenge_window_seconds: { type: integer }
        challenge_window_expired_at: { type: string, format: date-time }
        finalized_at: { type: string, format: date-time }
    ArtifactPda:
      type: object
      required: [pda_id, pda_version, pda_root, trust_tier, operational_class]
      properties:
        pda_id: { type: string, format: uuid }
        pda_version: { type: string }
        pda_root: { $ref: '#/components/schemas/Hex32' }
        trust_tier: { type: string, enum: [tier_a, tier_b, tier_c] }
        operational_class: { type: string, enum: [consumer, b2b_partner, regulated, legal_effect] }
    ArtifactRecipient:
      type: object
      required: [recipient_ref, schema_selector_digest]
      properties:
        recipient_ref: { type: string }
        recipient_pubkey_id: { type: string }
        schema_selector_digest: { $ref: '#/components/schemas/Hex32' }
    ArtifactPlaintext:
      type: object
      required: [schema_selector_digest, schema_digest, content_encoding]
      properties:
        schema_selector_digest: { $ref: '#/components/schemas/Hex32' }
        schema_digest: { $ref: '#/components/schemas/Hex32' }
        content_encoding: { type: string }
        fields: { type: object, additionalProperties: true }
        object_ref: { type: string }
        field_hashes: { type: object, additionalProperties: { $ref: '#/components/schemas/Hex32' } }
    IssuerAttestationBlock:
      type: object
      required: [status]
      properties:
        status: { type: string, enum: [not_configured, present] }
        issuer_id: { type: string }
        issuer_registry_ref: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        issuer_signing_key_id: { type: string }
        signature_alg: { type: string }
        signed_payload_digest: { $ref: '#/components/schemas/Hex32' }
        signature: { type: string }
        subject_commitment_v3: { $ref: '#/components/schemas/Hex32' }
        person_key_ref: { type: string }
        valid_from: { type: string, format: date-time }
        valid_until: { type: string, format: date-time }
        revocation_ref: { type: string }
    ProvenanceBlock:
      type: object
      required: [status]
      properties:
        status: { type: string, enum: [not_configured, present] }
        p15_attestations_root: { $ref: '#/components/schemas/Hex32' }
        attestor_registry_ref: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        field_attestations:
          type: array
          items: { $ref: '#/components/schemas/FieldProvenanceAttestation' }
    FieldProvenanceAttestation:
      type: object
      required: [field_path, field_hash, attestor_id, attestor_signing_key_id, signature_alg, signed_payload_digest, signature, merkle_proof]
      properties:
        field_path: { type: string }
        field_hash: { $ref: '#/components/schemas/Hex32' }
        attestor_id: { type: string }
        attestor_signing_key_id: { type: string }
        signature_alg: { type: string }
        signed_payload_digest: { $ref: '#/components/schemas/Hex32' }
        signature: { type: string }
        merkle_proof: { type: array, items: { $ref: '#/components/schemas/Hex32' } }
        valid_from: { type: string, format: date-time }
        valid_until: { type: string, format: date-time }
        revocation_ref: { type: string }
    SigmaEvidence:
      type: object
      required: [sigma, authority_ref, public_after_reveal]
      properties:
        sigma: { $ref: '#/components/schemas/Hex' }
        authority_ref: { $ref: '#/components/schemas/Hex32' }
        variant: { type: string }
        stanza_index: { type: integer }
        attestation_ref: { $ref: '#/components/schemas/Hex32' }
        phase: { type: integer, enum: [1, 2] }
        public_after_reveal: { type: boolean, const: true }
    SigmaBlock:
      type: object
      required: [sigma_lit, sigma_g3, sigma_g4]
      properties:
        sigma_subject: { $ref: '#/components/schemas/Hex' }
        sigma_lit: { $ref: '#/components/schemas/SigmaEvidence' }
        sigma_g3: { $ref: '#/components/schemas/SigmaEvidence' }
        sigma_g4: { $ref: '#/components/schemas/SigmaEvidence' }
        sigma_conditional: { type: array, items: { $ref: '#/components/schemas/SigmaEvidence' } }
    ChainProofs:
      type: object
      required: [chain_id, condition_engine_address, reveal_authorized_emitter, reveal_authorized_event_signature, reveal_authorized_topics, receipt_proof, commit_tx_hash, commit_block, commit_block_hash, reveal_authorized_tx_hash, reveal_authorized_log_index, reveal_authorized_block, reveal_authorized_block_hash, base_finality_confirmations]
      properties:
        chain_id: { type: integer }
        condition_engine_address: { $ref: '#/components/schemas/EvmAddress' }
        reveal_authorized_emitter: { $ref: '#/components/schemas/EvmAddress' }
        reveal_authorized_event_signature: { type: string }
        reveal_authorized_topics: { type: array, items: { $ref: '#/components/schemas/Hex32' } }
        receipt_proof: { $ref: '#/components/schemas/ReceiptProof' }
        commit_tx_hash: { $ref: '#/components/schemas/Hex32' }
        commit_block: { type: integer }
        commit_block_hash: { $ref: '#/components/schemas/Hex32' }
        reveal_authorized_tx_hash: { $ref: '#/components/schemas/Hex32' }
        reveal_authorized_log_index: { type: integer }
        reveal_authorized_block: { type: integer }
        reveal_authorized_block_hash: { $ref: '#/components/schemas/Hex32' }
        base_finality_confirmations: { type: integer }
        finalized_at: { type: string, format: date-time }
        challenge_window_expired_at: { type: string, format: date-time }
        condition_module: { $ref: '#/components/schemas/EvmAddress' }
        conditionRef: { $ref: '#/components/schemas/Hex32' }
        shred_registry_state_at_reveal: { type: string }
    ReceiptProof:
      type: object
      required: [proof_type, block_number, block_hash, log_index]
      properties:
        proof_type: { type: string }
        block_number: { type: integer }
        block_hash: { $ref: '#/components/schemas/Hex32' }
        log_index: { type: integer }
        proof_nodes: { type: array, items: { type: string } }
    RegistrySnapshots:
      type: object
      required: [authorization_block, authorization_block_hash, registry_contracts]
      properties:
        authorization_block: { type: integer }
        authorization_block_hash: { $ref: '#/components/schemas/Hex32' }
        registry_contracts: { type: object, additionalProperties: { $ref: '#/components/schemas/RegistrySnapshotRef' } }
        pda_registry: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        condition_module_registry: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        gate_authority_registries: { type: object, additionalProperties: { $ref: '#/components/schemas/RegistrySnapshotRef' } }
        shred_registry: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        issuer_registry: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        attestor_registry: { $ref: '#/components/schemas/RegistrySnapshotRef' }
        sd_registry: { $ref: '#/components/schemas/RegistrySnapshotRef' }
    ArtifactShredState:
      type: object
      required: [h_commit, shred_state]
      properties:
        h_commit: { $ref: '#/components/schemas/Hex32' }
        shred_state: { type: string }
        proof_shred: { $ref: '#/components/schemas/Hex32' }
        checked_at_block: { type: integer }
        checked_at_block_hash: { $ref: '#/components/schemas/Hex32' }
    ArtifactSdRefs:
      type: object
      required: [status]
      properties:
        status: { type: string, enum: [not_configured, present, failed, partial_failure] }
        sdMerkleRoot: { type: string }
        disclosure_refs: { type: array, items: { type: string } }
        revocation_refs: { type: array, items: { type: string } }
    ArtifactVerification:
      type: object
      required: [artifact_bundle_digest, verifier_version]
      properties:
        artifact_bundle_digest: { $ref: '#/components/schemas/Hex32' }
        verifier_version: { type: string }
        checks: { type: object, additionalProperties: true }
    PiiStatement:
      type: string
      enum: [recipient_filtered_plaintext_after_valid_reveal]
    WebhookEventType:
      type: string
      enum: [commit.finalized, commit.failed, sd.completed, sd.partial_failure, reveal.authorized, challenge.opened, challenge.resolved, reveal.ready_for_gate_signing, reveal.finalized, reveal.failed, g4.refused, shred.authorized, shred.challenge_opened, shred.finalized, halt.triggered, registry.deprecated, vault.retention_expiring, vault.shredded]
    CommitWebhookData:
      type: object
      required: [h_commit, status]
      properties: { h_commit: { $ref: '#/components/schemas/Hex32' }, status: { type: string } }
    SdWebhookData:
      type: object
      required: [h_commit, status]
      properties: { h_commit: { $ref: '#/components/schemas/Hex32' }, status: { type: string }, sdMerkleRoot: { type: string } }
    RevealWebhookData:
      type: object
      required: [authorizationId, h_commit, status]
      properties: { authorizationId: { $ref: '#/components/schemas/Hex32' }, h_commit: { $ref: '#/components/schemas/Hex32' }, status: { type: string }, artifact_bundle_digest: { $ref: '#/components/schemas/Hex32' } }
    ChallengeWebhookData:
      type: object
      required: [authorizationId, h_commit, status]
      properties: { authorizationId: { $ref: '#/components/schemas/Hex32' }, h_commit: { $ref: '#/components/schemas/Hex32' }, status: { type: string } }
    G4RefusalWebhookData:
      type: object
      required: [authorizationId, h_commit, reason_code]
      properties: { authorizationId: { $ref: '#/components/schemas/Hex32' }, h_commit: { $ref: '#/components/schemas/Hex32' }, reason_code: { type: string }, encrypted_reason_ref: { type: string } }
    ShredWebhookData:
      type: object
      required: [h_commit, status]
      properties: { h_commit: { $ref: '#/components/schemas/Hex32' }, status: { type: string }, proof_shred: { $ref: '#/components/schemas/Hex32' } }
    HaltWebhookData:
      type: object
      required: [halt_ref, status]
      properties: { halt_ref: { type: string }, status: { type: string }, encrypted_diagnostic_ref: { type: string } }
    RegistryWebhookData:
      type: object
      required: [registry_name, registry_ref]
      properties: { registry_name: { type: string }, registry_ref: { type: string }, effective_block: { type: integer } }
    VaultWebhookData:
      type: object
      required: [h_commit, status]
      properties: { h_commit: { $ref: '#/components/schemas/Hex32' }, status: { type: string }, retention_expires_at: { type: string, format: date-time } }
```

## App. B — Verification SDK contract (TypeScript types reference)

```ts
export type Hex = `0x${string}`;
export type Hex32 = Hex;

export type VerifyStatus = "pass" | "fail" | "skipped";

export type VerifyCheck = {
  status: VerifyStatus;
  code: string;
  message?: string;
  safe_refs?: Record<string, string | number | boolean>;
};

export type RegistrySnapshotRef = {
  registry_name: string;
  chain_id: number;
  registry_address: string;
  checked_block: number;
  checked_block_hash: Hex32;
  entry_digest: Hex32;
  lookup_key?: string;
  proof_ref?: string;
};

export type ChainProofs = {
  chain_id: number;
  condition_engine_address: string;
  reveal_authorized_emitter: string;
  reveal_authorized_event_signature: string;
  reveal_authorized_topics: Hex32[];
  receipt_proof: {
    proof_type: string;
    block_number: number;
    block_hash: Hex32;
    log_index: number;
    proof_nodes?: string[];
  };
  commit_tx_hash: Hex32;
  commit_block: number;
  commit_block_hash: Hex32;
  reveal_authorized_tx_hash: Hex32;
  reveal_authorized_log_index: number;
  reveal_authorized_block: number;
  reveal_authorized_block_hash: Hex32;
  base_finality_confirmations: number;
  finalized_at?: string;
  challenge_window_expired_at?: string;
  condition_module?: string;
  conditionRef?: Hex32;
  shred_registry_state_at_reveal?: string;
};

export type RegistrySnapshots = {
  authorization_block: number;
  authorization_block_hash: Hex32;
  registry_contracts: Record<string, RegistrySnapshotRef>;
  pda_registry?: RegistrySnapshotRef;
  condition_module_registry?: RegistrySnapshotRef;
  gate_authority_registries?: Record<string, RegistrySnapshotRef>;
  shred_registry?: RegistrySnapshotRef;
  issuer_registry?: RegistrySnapshotRef;
  attestor_registry?: RegistrySnapshotRef;
  sd_registry?: RegistrySnapshotRef;
};

export type IssuerAttestationBlock =
  | { status: "not_configured" }
  | {
      status: "present";
      issuer_id: string;
      issuer_registry_ref: RegistrySnapshotRef;
      issuer_signing_key_id: string;
      signature_alg: string;
      signed_payload_digest: Hex32;
      signature: string;
      subject_commitment_v3: Hex32;
      person_key_ref: string;
      valid_from?: string;
      valid_until?: string;
      revocation_ref?: string;
    };

export type FieldProvenanceAttestation = {
  field_path: string;
  field_hash: Hex32;
  attestor_id: string;
  attestor_signing_key_id: string;
  signature_alg: string;
  signed_payload_digest: Hex32;
  signature: string;
  merkle_proof: Hex32[];
  valid_from?: string;
  valid_until?: string;
  revocation_ref?: string;
};

export type ProvenanceBlock =
  | { status: "not_configured" }
  | {
      status: "present";
      p15_attestations_root: Hex32;
      attestor_registry_ref: RegistrySnapshotRef;
      field_attestations: FieldProvenanceAttestation[];
    };

export type ArtifactShredState = {
  h_commit: Hex32;
  shred_state: string;
  proof_shred?: Hex32;
  checked_at_block?: number;
  checked_at_block_hash?: Hex32;
};

export type ArtifactSdRefs = {
  status: "not_configured" | "present" | "failed" | "partial_failure";
  sdMerkleRoot?: string;
  disclosure_refs?: string[];
  revocation_refs?: string[];
};

export type RevealArtifactBundle = {
  bundle_version: string;
  canonicalization: {
    format: "JCS";
    rfc: "RFC8785";
    hash: "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))";
  };
  authorization: {
    authorizationId: Hex32;
    h_commit: Hex32;
    commit_version: "0x0302" | string;
    authorization_block: number;
    authorization_block_hash: Hex32;
    authorization_timestamp: string;
    conditionRef: Hex32;
    challenge_window_seconds: number;
    challenge_window_expired_at: string;
    finalized_at: string;
  };
  pda: {
    pda_id: string;
    pda_version: string;
    pda_root: Hex32;
    trust_tier: "tier_a" | "tier_b" | "tier_c";
    operational_class: "consumer" | "b2b_partner" | "regulated" | "legal_effect";
  };
  recipient: {
    recipient_ref: string;
    recipient_pubkey_id?: string;
    schema_selector_digest: Hex32;
  };
  plaintext: {
    schema_selector_digest: Hex32;
    schema_digest: Hex32;
    content_encoding: string;
    fields?: Record<string, unknown>;
    object_ref?: string;
    field_hashes?: Record<string, Hex32>;
  };
  issuer_attestation: IssuerAttestationBlock;
  provenance: ProvenanceBlock;
  sigma_block: SigmaBlock;
  chain_proofs: ChainProofs;
  registry_snapshots: RegistrySnapshots;
  shred_state: ArtifactShredState;
  sd_refs: ArtifactSdRefs;
  verification: {
    artifact_bundle_digest: Hex32;
    verifier_version: string;
    checks?: Record<string, unknown>;
  };
  pii_statement: "recipient_filtered_plaintext_after_valid_reveal";
};

export type SigmaBlock = {
  sigma_subject?: Hex;
  sigma_lit: SigmaEvidence;
  sigma_g3: SigmaEvidence;
  sigma_g4: SigmaEvidence;
  sigma_conditional?: SigmaEvidence[];
};

export type SigmaEvidence = {
  sigma: Hex;
  authority_ref: Hex32;
  variant?: string;
  stanza_index?: number;
  attestation_ref?: Hex32;
  phase?: 1 | 2;
  public_after_reveal: true;
};

export type VerifyArtifactOptions = {
  chainRpcUrl?: string;
  registryOverrides?: Record<string, string>;
  requireOnlineRegistryChecks?: boolean;
  now?: Date;
  expectedRecipientRef?: string;
};

export type VerifyArtifactResult = {
  overall: VerifyStatus;
  artifact_bundle_digest: Hex32;
  checks: {
    canonicalization: VerifyCheck;
    chainProof: VerifyCheck;
    pdaRoot: VerifyCheck;
    registrySnapshots: VerifyCheck;
    endpointAttestation: VerifyCheck;
    issuerAttestation: VerifyCheck;
    provenance: VerifyCheck;
    sigmaSubject: VerifyCheck;
    sigmaLit: VerifyCheck;
    sigmaG3: VerifyCheck;
    sigmaG4: VerifyCheck;
    sigmaConditional: VerifyCheck;
    shredState: VerifyCheck;
    recipientSelector: VerifyCheck;
    sdRefs: VerifyCheck;
  };
  safe_refs: {
    authorizationId: Hex32;
    h_commit: Hex32;
    pda_root?: Hex32;
    authorization_block?: number;
  };
};

export type SdOutput = {
  status: "complete" | "failed" | "partial_failure" | "skipped" | "not_configured";
  authorizationId?: Hex32;
  h_commit?: Hex32;
  pda_root?: Hex32;
  partner_id?: string;
  pda_id?: string;
  schema_digest?: Hex32;
  sdMerkleRoot?: string;
  sd_plan_digest?: Hex32;
  cleartext?: unknown[];
  claims?: unknown[];
  failures?: unknown[];
};

export type VerifySdOptions = {
  checkExpiry?: boolean;
  checkRevocation?: boolean;
  now?: Date;
};

export type VerifySdResult = {
  overall: VerifyStatus;
  checks: Record<string, VerifyCheck>;
};

export type WebhookHeaders = {
  "x-cealis-signature": string;
  "x-cealis-timestamp": string;
  "x-cealis-event": string;
  "x-cealis-delivery": string;
};

export type WebhookVerificationResult = {
  overall: VerifyStatus;
  event_id?: string;
  event_type?: string;
  checks: {
    timestamp: VerifyCheck;
    signature: VerifyCheck;
    replayWindow: VerifyCheck;
  };
};

export async function verifyArtifactBundle(
  bundle: RevealArtifactBundle,
  options?: VerifyArtifactOptions
): Promise<VerifyArtifactResult>;

export async function verifySdOutput(
  sd: SdOutput,
  options?: VerifySdOptions
): Promise<VerifySdResult>;

export async function verifyWebhook(
  rawBody: Uint8Array,
  headers: WebhookHeaders,
  secret: Uint8Array,
  now?: Date
): Promise<WebhookVerificationResult>;
```

SDK implementation constraints:

- Verification functions return structured checks, not only booleans.
- Raw σ values may be parsed as evidence but are not logged by default.
- Shares, decap material, DEK, plaintext outside the bundle, SD salts, and witnesses are not accepted as inputs.
- `verifyArtifactBundle` must verify on-chain event data independently when `requireOnlineRegistryChecks = true`.
- `verifyWebhook` verifies HMAC over `utf8(headers["x-cealis-timestamp"]) "." rawBody` before JSON parse.

## App. C — Scope-out reference

| Out of S2-5 | Owning spec |
|---|---|
| TAG constants, byte layouts, `commit_AAD`, AEAD, Shamir, stanza wrap | S2-1 |
| Contract ABI, events, registries, refusal, shred, Mode 3 rejection | S2-2 |
| Lit/dcipher/drand/G4 SDK calls, transport libraries, combiner binary hardening | S2-3 |
| PDA+ governance, PDA emission, class table, default tables | S2-4 |
| SD circuits, commitments, proofs, salts, revocation | S2-7 |
| Operational ceremonies, cutovers, incident runbooks, key rotations | S2-6 / S3-1 |
| Generated SDK docs and package reference | S3-4 |

This document deliberately avoids redefining those surfaces. Where an implementation needs detail from an out-of-scope owner, it imports the owner directly and treats any S2-5 prose as routing guidance only.
