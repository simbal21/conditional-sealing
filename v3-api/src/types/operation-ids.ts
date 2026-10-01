// OpenAPI operationId catalog — verbatim from S2-5 App. A (lines 1255-1655).
//
// LOCKED at Phase A. Spec body grep-verified 2026-05-11: 29 entries total.
// Phase A foundation test asserts count = 29.
//
// PHASE-PLAN §0 sanity check noted "brief said 27 — spec App. A has 29";
// the spec is authoritative. SPEC-COMPLIANCE-GUARD-M5.md §1 records.
//
// Phase F tripwire greps assert every operationId appears in source under
// `src/{partner,subject,ingest,reveal,vault,verify,webhooks,g4}/` (per §1.7).

export const OPERATION_IDS = [
  // §2 G4 ingestion endpoint (Mode A — shipping default)
  "getG4EndpointAttestation",
  "createModeAIngestion",
  "getIngestionStatus",
  // §3 Reveal delivery surface (combiner protocol) — event-driven, no POST
  "getRevealStatus",
  "getCombinerManifest",
  "getRevealArtifactBundle",
  // §5 Partner API surface
  "listPartnerPdas",
  "getPartnerPda",
  "createOnboardingLink",
  "getPartnerEscrowStatus",
  "createPartnerShredRequest",
  "getPartnerRevealStatus",
  "getPartnerObligationStatus",
  "getPartnerShredStatus",
  // §6 Subject-facing API surface
  "createSubjectWebAuthnChallenge",
  "verifySubjectWebAuthn",
  "revokeSubjectSession",
  "listSubjectEscrows",
  "getSubjectEscrowStatus",
  "getSubjectVaultBlob",
  "exportSubjectAuditLog",
  "getSubjectRetention",
  "createSubjectShredRequest",
  // §6.3 Pre-σ verifier surface
  "getPreSigmaPayload",
  "submitPreSigmaConfirmations",
  // §8 Vault access semantics (retention surface)
  "getVaultRetention",
  // §9 Verification SDKs (server-side verify cross-check + manifests)
  "verifyArtifactBundle",
  "getVerificationNetworks",
  "getSdkVersions",
] as const;

export type OperationId = (typeof OPERATION_IDS)[number];

/**
 * Canonical count — Phase A foundation test asserts equality.
 */
export const OPERATION_ID_COUNT: number = OPERATION_IDS.length;

/**
 * Map each operationId to: HTTP method, path, auth scheme, idempotency-required.
 * Phase B/C/D fill route handlers behind these slots; Phase F tripwire grep
 * asserts every operationId has a Fastify route registered.
 *
 * Auth schemes:
 *   - `partner_hmac` — §1.2 + §5.1 (8 scopes)
 *   - `subject_bearer` — §6.1 WebAuthn-anchored Bearer
 *   - `onboarding_token` — §2.7 + §6.3 token-bearing URL
 *   - `public` — no auth (network manifest, sdk versions)
 *   - `webauthn_challenge` — challenge/assertion, no idempotency-key
 */
export type AuthScheme =
  | "partner_hmac"
  | "subject_bearer"
  | "onboarding_token"
  | "public"
  | "webauthn_challenge";

export interface OperationDescriptor {
  readonly method: "GET" | "POST" | "DELETE";
  readonly path: string;
  readonly auth: AuthScheme;
  readonly idempotencyRequired: boolean;
}

export const OPERATION_TO_PATH: Readonly<Record<OperationId, OperationDescriptor>> = {
  // §2 G4 ingestion
  getG4EndpointAttestation: { method: "GET", path: "/v1/g4/attestation", auth: "partner_hmac", idempotencyRequired: false },
  createModeAIngestion: { method: "POST", path: "/v1/ingestions", auth: "partner_hmac", idempotencyRequired: true },
  getIngestionStatus: { method: "GET", path: "/v1/ingestions/:h_commit", auth: "partner_hmac", idempotencyRequired: false },
  // §3 reveal (event-driven; partner pulls manifests + bundles)
  getRevealStatus: { method: "GET", path: "/v1/reveals/:authorizationId", auth: "partner_hmac", idempotencyRequired: false },
  getCombinerManifest: { method: "GET", path: "/v1/reveals/:authorizationId/delivery-manifest", auth: "partner_hmac", idempotencyRequired: false },
  getRevealArtifactBundle: { method: "GET", path: "/v1/reveals/:authorizationId/artifact-bundles/:recipient_ref", auth: "partner_hmac", idempotencyRequired: false },
  // §5 partner API
  listPartnerPdas: { method: "GET", path: "/v1/partners/me/pdas", auth: "partner_hmac", idempotencyRequired: false },
  getPartnerPda: { method: "GET", path: "/v1/partners/me/pdas/:pda_id", auth: "partner_hmac", idempotencyRequired: false },
  createOnboardingLink: { method: "POST", path: "/v1/partners/me/onboarding-links", auth: "partner_hmac", idempotencyRequired: true },
  getPartnerEscrowStatus: { method: "GET", path: "/v1/partners/me/escrows/:h_commit", auth: "partner_hmac", idempotencyRequired: false },
  createPartnerShredRequest: { method: "POST", path: "/v1/partners/me/escrows/:h_commit/shred-requests", auth: "partner_hmac", idempotencyRequired: true },
  getPartnerRevealStatus: { method: "GET", path: "/v1/partners/me/reveals/:authorizationId", auth: "partner_hmac", idempotencyRequired: false },
  getPartnerObligationStatus: { method: "GET", path: "/v1/partners/me/obligations/:obligation_id", auth: "partner_hmac", idempotencyRequired: false },
  getPartnerShredStatus: { method: "GET", path: "/v1/partners/me/shred-requests/:shred_request_id", auth: "partner_hmac", idempotencyRequired: false },
  // §6 subject
  createSubjectWebAuthnChallenge: { method: "POST", path: "/v1/subjects/webauthn/challenge", auth: "webauthn_challenge", idempotencyRequired: false },
  verifySubjectWebAuthn: { method: "POST", path: "/v1/subjects/webauthn/verify", auth: "webauthn_challenge", idempotencyRequired: false },
  revokeSubjectSession: { method: "POST", path: "/v1/subjects/sessions/revoke", auth: "subject_bearer", idempotencyRequired: true },
  listSubjectEscrows: { method: "GET", path: "/v1/subjects/me/escrows", auth: "subject_bearer", idempotencyRequired: false },
  getSubjectEscrowStatus: { method: "GET", path: "/v1/subjects/me/escrows/:h_commit", auth: "subject_bearer", idempotencyRequired: false },
  getSubjectVaultBlob: { method: "GET", path: "/v1/subjects/me/escrows/:h_commit/vault-blob", auth: "subject_bearer", idempotencyRequired: false },
  exportSubjectAuditLog: { method: "GET", path: "/v1/subjects/me/audit-log", auth: "subject_bearer", idempotencyRequired: false },
  getSubjectRetention: { method: "GET", path: "/v1/subjects/me/retention", auth: "subject_bearer", idempotencyRequired: false },
  createSubjectShredRequest: { method: "POST", path: "/v1/subjects/me/escrows/:h_commit/shred-requests", auth: "subject_bearer", idempotencyRequired: true },
  // §6.3 pre-σ
  getPreSigmaPayload: { method: "GET", path: "/v1/onboarding/:token/pre-sigma-payload", auth: "onboarding_token", idempotencyRequired: false },
  submitPreSigmaConfirmations: { method: "POST", path: "/v1/onboarding/:token/pre-sigma-confirmations", auth: "onboarding_token", idempotencyRequired: true },
  // §8 vault retention
  getVaultRetention: { method: "GET", path: "/v1/vault/retention/:h_commit", auth: "partner_hmac", idempotencyRequired: false },
  // §9 verification SDKs
  verifyArtifactBundle: { method: "POST", path: "/v1/verify/artifact-bundles", auth: "partner_hmac", idempotencyRequired: false },
  getVerificationNetworks: { method: "GET", path: "/v1/verify/networks", auth: "public", idempotencyRequired: false },
  getSdkVersions: { method: "GET", path: "/v1/verify/sdk-versions", auth: "public", idempotencyRequired: false },
} as const;
