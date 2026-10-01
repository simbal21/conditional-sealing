// HMAC auth + subject session types — verbatim from S2-5 §1.2, §5.1, §6.1, §7.2.
//
// LOCKED at Phase A. Phase D implements middleware bodies.

import type { ApiScope } from "./scopes.js";

/**
 * Partner request headers — §1.2 lines 152-159.
 */
export interface PartnerHmacHeaders {
  "x-cealis-key-id": string; // opaque partner key id
  "x-cealis-timestamp": string; // unix seconds
  "x-cealis-nonce": string; // 128-bit random base64url
  "x-cealis-signature": string; // sha256=<hex HMAC-SHA256(signing_secret, canonical_request)>
  "idempotency-key"?: string; // required on mutating endpoints
}

/**
 * Canonical-request preimage — §1.2 lines 164-171 verbatim.
 *
 *   METHOD "\n"
 *   PATH_WITH_QUERY "\n"
 *   X-Cealis-Timestamp "\n"
 *   X-Cealis-Nonce "\n"
 *   sha256(raw_request_body)
 */
export interface CanonicalRequestInput {
  method: "GET" | "POST" | "DELETE";
  pathWithQuery: string; // includes ?query if present
  timestamp: string; // unix seconds, decimal
  nonce: string; // base64url
  rawRequestBody: Uint8Array; // body bytes BEFORE JSON parse
}

/**
 * Partner principal — extracted from validated HMAC. Phase D auth middleware
 * attaches to request context.
 */
export interface PartnerPrincipal {
  partner_id: string;
  key_id: string;
  scopes: ReadonlySet<ApiScope>;
}

/**
 * Subject principal — extracted from validated Bearer token. Phase D
 * webauthn-verify middleware sets after challenge consumption.
 */
export interface SubjectPrincipal {
  user_id: string;
  session_id: string; // server-side opaque (SHA-256 hashed in DB)
  expires_at: string; // ISO-8601
}

/**
 * Onboarding-token principal — extracted from {token} path param.
 * Used by §2.7 public ingest + §6.3 pre-σ.
 */
export interface OnboardingTokenPrincipal {
  onboarding_link_id: string;
  partner_id: string;
  pda_id: string;
  token: string;
  expires_at?: string;
}

/**
 * Replay-window constants — locked at Phase A.
 *
 * Per §1.2 line 175 (partner request) + §7.2 line 837 (webhook): 300s.
 * Per §1.2 line 175 (nonce reuse): 24h (86400s).
 */
export const HMAC_REPLAY_WINDOW_SECONDS = 300 as const;
export const HMAC_NONCE_REUSE_WINDOW_SECONDS = 86400 as const;

/**
 * Subject session TTL — locked at Phase A.
 *
 * Per §6.1 line 750: SHA-256 hash, 7-day expiry, revocable.
 */
export const SUBJECT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
