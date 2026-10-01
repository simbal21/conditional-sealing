// Subject WebAuthn credential store seam.
//
// Security-audit-2026-06-02 F-1: real WebAuthn assertion verification requires
// looking up the registered credential (its public key + signCounter + bound
// user_id) by the credentialId carried in the assertion. The user_id is derived
// from the matched credential record — NEVER from the client-supplied request
// body.
//
// DESIGN-SENSITIVE: where these credential records ultimately live (Drizzle
// `user_accounts` row, on-chain anchor, KMS-sealed blob) and how registration
// populates them is a Phase D/R2b wiring decision. This module locks only the
// minimal lookup seam the verifier needs; the in-memory impl is for tests and
// the synthetic scaffold. When no credential matches, the verifier HARD-FAILS
// (no session) per Rule 12 — a verify path must never fake-success.

import type { Base64URLString, WebAuthnCredential } from "@simplewebauthn/server";

/**
 * A registered subject passkey credential, as required to verify an assertion.
 * `user_id` is the server-trusted identity bound at registration time — the
 * authority for who a successful assertion authenticates AS.
 */
export interface SubjectWebAuthnCredentialRecord {
  /** Server-side subject identity bound at registration. Source of truth for user_id. */
  readonly user_id: string;
  /** The WebAuthn credential (id, COSE public key, signCounter, transports). */
  readonly credential: WebAuthnCredential;
  readonly revoked_at?: string | null;
}

export interface SubjectWebAuthnCredentialReader {
  /**
   * Resolve a registered credential by its base64url credentialId.
   * Returns undefined when no live credential matches (→ verifier rejects).
   */
  getByCredentialId(
    credentialId: Base64URLString,
  ): SubjectWebAuthnCredentialRecord | undefined | Promise<SubjectWebAuthnCredentialRecord | undefined>;
}

export interface SubjectWebAuthnCredentialWriter {
  /** Persist the post-verification signCounter (replay defense across assertions). */
  updateCounter(credentialId: Base64URLString, newCounter: number): void | Promise<void>;
}

export class InMemorySubjectWebAuthnCredentialStore
  implements SubjectWebAuthnCredentialReader, SubjectWebAuthnCredentialWriter
{
  private readonly byId = new Map<string, SubjectWebAuthnCredentialRecord>();

  register(record: SubjectWebAuthnCredentialRecord): void {
    this.byId.set(record.credential.id, record);
  }

  getByCredentialId(credentialId: Base64URLString): SubjectWebAuthnCredentialRecord | undefined {
    return this.byId.get(credentialId);
  }

  updateCounter(credentialId: Base64URLString, newCounter: number): void {
    const existing = this.byId.get(credentialId);
    if (!existing) return;
    this.byId.set(credentialId, {
      ...existing,
      credential: { ...existing.credential, counter: newCounter },
    });
  }
}
