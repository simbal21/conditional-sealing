> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# HTTP Boundary Adversarial Audit — 2026-06-02 (HEAD e87c108)

Scope: v3-api/src/ (ingest, partner, subject, verify, redaction, auth) + v3-configurator/src/pda/

## Live-exposure context (severity calibration anchor)
`createFastifyApp` (server/index.ts) mounts ONLY:
- POST /v1/verify/artifact-bundles
- GET /v1/verification/networks, /v1/verification/sdk-versions
- POST /internal/reveal/initiate
- GET /healthz

`registerSubjectRoutes`, `registerIngestRoutes`, `registerPartnerRoutes` are DEFINED but
NOT invoked anywhere (grep: zero call sites outside their own `export function`). They reach a
live server only once R2b worker-2 wires them. So the auth/schema findings below are LATENT —
present in code at HEAD, will be exploitable on the partner/subject/ingest surface the moment
those aggregators are mounted. I flag them because they are real code-path defects that an
adversary hits as soon as the surface goes live, and the mitigating comments claim protection
that the code does not deliver.

`server/bin.ts` `wireProductionDeps()` throws "NOT YET WIRED" — the bin cannot boot a real
server today. Tests call createFastifyApp directly.

---

## F-1 [HIGH/latent] WebAuthn verify is a fake-success auth handler — issues sessions for arbitrary user_id with no signature
File: v3-api/src/webauthn/verify.ts:19-48 (+ challenge.ts, routes-webauthn-verify.ts, routes-webauthn-challenge.ts)

`verifyWebAuthnAssertion` performs NO WebAuthn assertion verification. It:
1. consumes the challenge by id,
2. checks `challenge.challenge === input.assertion.challenge` (the client echoing back the
   random hex that the /challenge endpoint just RETURNED to it — see routes-webauthn-challenge.ts:22),
3. sets `userId = input.assertion.user_id ?? challenge.user_id` — i.e. the user_id is taken
   from the CLIENT-SUPPLIED assertion body, unbound to any credential,
4. mints a full bearer session for that user_id.

No clientDataJSON, no authenticatorData, no signature over `authenticatorData ‖ sha256(clientDataJSON)`,
no registered-credential public-key lookup, no RP-ID/origin/type/challenge-in-clientData binding,
no signCounter. The "assertion" type only carries `{ challenge, user_id?, authenticator_digest? }`
and none of the cryptographic fields are checked.

Exploit: POST /v1/subjects/webauthn/challenge {purpose:"login"} → receive {challenge_id, challenge}.
POST /v1/subjects/webauthn/verify {challenge_id, assertion:{challenge:<echoed>, user_id:"<victim>"}}
→ receive a valid bearer_token for <victim>. Full pre-auth account takeover of any subject once
the subject surface is mounted; subject routes (escrows, vault-blob, audit-log, retention,
shred-request) are all gated only by this bearer session.

Fix: implement real WebAuthn verification (@simplewebauthn/server, already used in V1 per
internal frontend rules) — verify assertion signature against the stored credential public key,
bind challenge from clientDataJSON, check RP ID hash, origin, type=="webauthn.get", and signCounter.
Never derive user_id from the request body; derive it from the credential record matched by
credentialId. Until implemented, the route must hard-fail (Rule 12 — no fake-success stubs in an
auth path), not issue sessions.

## F-2 [MEDIUM/latent] Ingest body schema with `additionalProperties:false` is never bound to Fastify — runtime validation absent
File: v3-api/src/ingest/routes-create-mode-a.ts:142-169 (schema), 655-682 (route)

`ModeAIngestionRequestSchema` carries `{ additionalProperties: false }` with an inline comment
(lines 163-167) claiming it "closes the prototype-pollution + smuggled-field surface.
Security-audit-2026-05-14 TS-API-F-01 / TS-API-F-04." But `app.post("/v1/ingestions", ...)` is
registered with NO `{ schema: { body: ... } }` option — the schema is only attached to the
discarded RouteRegistry (OpenAPI descriptor), so Fastify performs ZERO body validation. Confirmed:
grep shows only the two shred-request routes bind a Fastify `schema:` (and those are params-only,
no body). The TS-API-F-01/F-04 hardening is dead at runtime; unknown top-level keys are accepted,
and no type/format/required enforcement happens except the handful of manual `ensureHex32` checks
inside the handler.

Exploit: send extra/unknown keys, wrong-typed fields, or oversized payloads to /v1/ingestions.
Manual checks only cover authorizationIdCandidate/preflight_context_digest/schema_digest/
client_attestation_digest hex shape; everything else (pda_id, partner_id, nested objects,
payload_classification) is unvalidated structure flowing into digest computation, PDA inspection,
and vault write. Same latent gap on all non-shred POST routes (webauthn challenge/verify,
pre-sigma confirmations).

Fix: pass the TypeBox schema as `{ schema: { body: ModeAIngestionRequestSchema } }` on the
`app.post` options so Fastify's validator enforces `additionalProperties:false` + types at the
edge. Do the same for every POST route. Also set a `bodyLimit` at app construction — the comment
on line 167 references "server.ts bodyLimit" but `Fastify(deps.fastifyOptions ?? {logger:false})`
in server/index.ts sets none, so plaintext_payload (Type.Unknown) is bounded only by Fastify's
1 MB default rather than an enforced project limit.

## F-3 [MEDIUM/latent] G4 endpoint-attestation GET fails OPEN: malformed hex coerced to zero-hash, no partner auth, no body schema
File: v3-api/src/ingest/routes-get-attestation.ts:39-41, 47-48, 59-72, 87-104

`assertHex(value, fallback)` returns an all-zero 32-byte hash when the input is NOT valid hex,
instead of rejecting. The route binds no Fastify query schema (the TypeBox
`G4EndpointAttestationQuerySchema` is registered only on the discarded RouteRegistry, and is
`additionalProperties:true` anyway). So GET /v1/g4/attestation?authorizationIdCandidate=garbage
silently returns an attestation bound to authorizationId 0x000…000 / preflight_digest 0x000…000
rather than a 400. `partner_id` also defaults to a hardcoded UUID (line 47) when omitted, and the
route has no auth preHandler as written, so any caller can mint a (synthetic) G4 attestation for
any pda_id without proving partner ownership.

Exploit: request attestations with malformed or absent fields → receive zero-bound attestation
artifacts; or enumerate pda_ids without partner credentials. Fail-open coercion can mask client
bugs and produce artifacts whose bindings don't match the caller's intended commit.

Fix: bind the query schema to Fastify and make hex fields required+pattern-validated (400 on
miss). Remove the zero-hash fallback — reject malformed hex. Require partner-HMAC auth + scope on
this route; do not default partner_id to a constant.

## F-4 [LOW/by-design-Phase1] Ingest trusts client-asserted G4 verification_checks verbatim — no server-side re-verification
File: v3-api/src/g4/preflight-recompute.ts:32-89 ; attestation-builder.ts:116-173

`verifyAttestationPreflightOrThrow` gates ingest on the four G4 checks but only reads
`preflight.verification_checks.<x>.status === "pass"` — values the CLIENT put in its own request
body. The server never re-queries the Lit assignment registry, Lit DCAP quote, G3 committee
pubkey, or G4 authority registry. The `sameDigest` check compares
`header_attestation_digest === client_attestation_digest` (both attacker-controlled) and
`preflight.digest === client_attestation_digest`, but the server does not recompute
`preflight.digest` from the attestation contents (`jcsDigestHex32(preflightWithoutDigest)`), so a
self-consistent forged attestation with all checks "pass" is accepted. The attestation-builder
itself is fully synthetic (passingCheck hardcoded "pass", zero registry addresses, "synthetic"
operator/measurement) — consistent with the documented Phase-1 synthetic scaffold, so I score this
LOW and flag it as a phase-honesty item, not a net-new break: when G4 Phase-2 / real registries
land, the ingest path MUST recompute `attestation_preflight.digest` and independently verify each
of the four checks against on-chain registry snapshots rather than trusting the body. Leaving the
trust-the-body shape in place is the risk to track.

Fix (forward): on the ingest path, recompute the attestation digest from contents and verify each
of the four checks against the committed registry snapshots (registry_refs entry_digest +
proof_ref) read at commit_block — never accept self-reported status. Add a test that a forged
all-pass attestation is rejected.

## F-5 [INFO] Log/error PII redaction (sanitize/pinoLogFormatter) is implemented but never wired
File: v3-api/src/redaction/log-sanitize.ts:29-93

`sanitize`/`pinoLogFormatter` exist but grep shows zero call sites — no Pino instance installs the
formatter, and createFastifyApp defaults to `logger:false`. The §10.2 forbidden-token redaction at
log egress is therefore non-operational. No live leak today (logger off, sensitive surfaces not
mounted), but when logging is enabled and subject/ingest routes go live, error bodies and log lines
are not run through the redactor. Minor heuristic gap noted: the key-name heuristic checks
`lc === "salt"` which would not catch a key literally named `sd_salt` (the value-pattern
`/\bsd_salt\b/i` does catch a value, so net coverage holds via value scan).

Fix: wire `pinoLogFormatter` into the Fastify logger config and route the Fastify error handler
output through `sanitize` before serialization; add the missing key-name variants.

## Checked and found SOUND (no finding)
- Subject routes IDOR: all key by `${principal.user_id}:${h_commit}` (routes-list-escrows.ts:134,
  get-vault-blob.ts:6) → no cross-subject access.
- Partner routes IDOR: all key by `${partner_id}:${h_commit}` (routes-get-escrow.ts:6) → partner-scoped.
- HMAC middleware (hmac-middleware.ts): constant-time compare, 300s replay window
  (HMAC_REPLAY_WINDOW_SECONDS), nonce single-use via NonceStore, body bound via sha256 in canonical
  request. Minor: nonce consumed before signature verify (line 58 vs 78) — random per-request nonces
  make this low-impact.
- Idempotency store: request-digest conflict detection correct (idempotency-middleware.ts:31-38).
- Internal reveal route (routes-internal-reveal-initiate.ts): strict hex32 validation on all id
  fields; phase-clearance minted live; documented platform-edge access policy (no app-level auth by
  design, must be blocked at ingress — operational control, verify deployment enforces it).
- Configurator PDA verify.ts / triple-root-guard.ts: recompute-and-compare integrity, sound; not
  HTTP-exposed (internal tooling).
- Subject/partner shred routes bind params h_commit pattern (the only routes with a Fastify schema).
