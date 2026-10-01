// Partner API scopes — verbatim from S2-5 §5.1 (lines 661-668).
//
// LOCKED at Phase A. Spec body grep-verified 2026-05-11: 8 entries.
// Phase A foundation test asserts count = 8.

export const API_SCOPES = [
  "pda:read",
  "onboarding_link:create",
  "ingestion:create",
  "escrow:read",
  "reveal:read",
  "webhook:manage",
  "vault:read_partner",
  "verification:read",
] as const;

export type ApiScope = (typeof API_SCOPES)[number];

export const API_SCOPE_COUNT: number = API_SCOPES.length;

/**
 * Route scope requirements — computed from §5.2-§5.7 prose + §8 vault + §9 verify.
 * Per-operation scope binding. Phase D auth middleware consumes; partner without
 * `reveal:read` cannot hit `getRevealArtifactBundle`.
 *
 * Subject + onboarding + webauthn-challenge routes have NO scope requirement
 * (auth scheme is subject_bearer / onboarding_token / webauthn_challenge — not
 * scoped via partner API key).
 */
import type { OperationId } from "./operation-ids.js";

export const ROUTE_SCOPE_REQUIREMENTS: Partial<Record<OperationId, ApiScope>> = {
  // §2 G4 ingestion — partner-side endpoints
  getG4EndpointAttestation: "ingestion:create",
  createModeAIngestion: "ingestion:create",
  getIngestionStatus: "escrow:read",
  // §3 reveal
  getRevealStatus: "reveal:read",
  getCombinerManifest: "reveal:read",
  getRevealArtifactBundle: "reveal:read",
  // §5 partner
  listPartnerPdas: "pda:read",
  getPartnerPda: "pda:read",
  createOnboardingLink: "onboarding_link:create",
  getPartnerEscrowStatus: "escrow:read",
  createPartnerShredRequest: "vault:read_partner",
  getPartnerRevealStatus: "reveal:read",
  getPartnerObligationStatus: "escrow:read",
  getPartnerShredStatus: "vault:read_partner",
  // §8 vault retention
  getVaultRetention: "vault:read_partner",
  // §9 verify SDK (server-side cross-check route)
  verifyArtifactBundle: "verification:read",
} as const;
