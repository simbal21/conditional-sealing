// Subject WebAuthn assertion verification.
//
// Security-audit-2026-06-02 F-1 (HIGH): the prior implementation performed NO
// cryptographic verification — it consumed the challenge, compared the client's
// echoed-back challenge string, then minted a bearer session for the
// CLIENT-SUPPLIED user_id. That is a pre-auth account-takeover of any subject.
//
// This implementation performs a real WebAuthn assertion verification via
// @simplewebauthn/server (the same library V1 uses per internal frontend rules):
//   - looks up the REGISTERED credential by the assertion's credentialId,
//   - verifies the assertion signature over authenticatorData ‖ sha256(clientDataJSON)
//     against that credential's stored COSE public key,
//   - binds the challenge from clientDataJSON to the server-issued challenge,
//   - checks RP ID hash, origin, type == "webauthn.get", and signCounter,
//   - derives user_id from the MATCHED CREDENTIAL RECORD — never from the body,
//   - persists the advanced signCounter (cross-assertion replay defense).
//
// When the credential-store seam is not wired, or no live credential matches,
// or verification fails, the route HARD-FAILS (no session) per Rule 12 — a
// verify path must never fake-success.

import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from "@simplewebauthn/server";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import type { SubjectPrincipal } from "../types/auth.js";
import type { InMemoryWebAuthnChallengeStore } from "./challenge.js";
import type { InMemorySubjectSessionStore } from "./session.js";
import type { SubjectWebAuthnCredentialReader, SubjectWebAuthnCredentialWriter } from "./credential-store.js";

/**
 * Server-locked RP binding for assertion verification.
 *
 * Mirrors V1's WEBAUTHN_RP_ID / WEBAUTHN_ORIGIN (see internal deployment rules
 * "WebAuthn Env Vars"). Locked at the composition root; never derived from the
 * request.
 */
export interface WebAuthnVerificationConfig {
  readonly rpId: string;
  readonly origin: string | readonly string[];
  readonly requireUserVerification?: boolean;
}

/**
 * The verified-assertion payload submitted by the subject's browser, i.e. the
 * JSON shape produced by @simplewebauthn/browser's startAuthentication().
 *
 * Note: there is NO `user_id` field — identity is established cryptographically
 * via the matched credential, not asserted by the client.
 */
export type WebAuthnAssertion = AuthenticationResponseJSON;

export interface WebAuthnSessionResult {
  readonly session: SubjectPrincipal;
  readonly bearer_token: string;
  readonly expires_at: string;
  readonly phase_trust_statement: "passkey_only_qtsp_deferred_stage_3_5";
}

export async function verifyWebAuthnAssertion(input: {
  readonly challenge_id: string;
  readonly assertion: WebAuthnAssertion;
  readonly challenges: InMemoryWebAuthnChallengeStore;
  readonly sessions: InMemorySubjectSessionStore;
  readonly credentials?: SubjectWebAuthnCredentialReader & Partial<SubjectWebAuthnCredentialWriter>;
  readonly config?: WebAuthnVerificationConfig;
  readonly now?: Date;
  readonly correlationId?: string;
}): Promise<WebAuthnSessionResult> {
  const now = input.now ?? new Date();
  const correlationId = input.correlationId ?? "webauthn";

  // (0) The credential-store + RP-binding seam MUST be wired. Until then we
  //     HARD-FAIL — no session — rather than fall back to the removed
  //     fake-success path (Rule 12). DESIGN-SENSITIVE: credential persistence +
  //     registration are Phase D/R2b wiring.
  if (!input.credentials || !input.config) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
        detail: "WebAuthn verification is not available: credential store / RP binding not wired.",
      }),
    );
  }

  // (1) Consume the server-issued challenge. Single-use; expiry-checked in the store.
  const challenge = input.challenges.consume(input.challenge_id, now);
  if (!challenge) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
        detail: "WebAuthn challenge is expired, consumed, or unknown.",
      }),
    );
  }

  // (2) Look up the registered credential by the assertion's credentialId.
  //     A missing/revoked credential is a rejection, never a new session.
  const credentialId = input.assertion.id;
  const record =
    typeof credentialId === "string" && credentialId.length > 0
      ? await input.credentials.getByCredentialId(credentialId)
      : undefined;
  if (!record || record.revoked_at) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
        detail: "No registered passkey credential matched the assertion.",
      }),
    );
  }

  // (3) Cryptographically verify the assertion against the stored public key,
  //     binding challenge / RP ID / origin / type / signCounter.
  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response: input.assertion,
      expectedChallenge: challenge.challenge,
      expectedOrigin: input.config.origin as string | string[],
      expectedRPID: input.config.rpId,
      credential: record.credential,
      expectedType: "webauthn.get",
      requireUserVerification: input.config.requireUserVerification ?? true,
    });
  } catch {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
        detail: "WebAuthn assertion signature verification failed.",
      }),
    );
  }
  if (!verification.verified) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
        detail: "WebAuthn assertion could not be verified.",
      }),
    );
  }

  // (4) Persist the advanced signCounter (cross-assertion replay defense).
  await input.credentials.updateCounter?.(record.credential.id, verification.authenticationInfo.newCounter);

  // (5) Mint the session for the user_id BOUND TO THE CREDENTIAL — not the body.
  const created = input.sessions.create({ user_id: record.user_id, now });
  return {
    session: {
      user_id: created.record.user_id,
      session_id: created.record.session_id,
      expires_at: created.record.expires_at,
    },
    bearer_token: created.token,
    expires_at: created.record.expires_at,
    phase_trust_statement: "passkey_only_qtsp_deferred_stage_3_5",
  };
}
