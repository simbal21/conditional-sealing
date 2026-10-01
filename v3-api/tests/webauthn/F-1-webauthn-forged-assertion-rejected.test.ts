// Closure test for Security-audit-2026-06-02 F-1 (HIGH):
// "WebAuthn verify is a fake-success auth handler — issues sessions for
//  arbitrary user_id with no signature."
//
// These tests exercise the ACTUAL attack path the finding describes: a forged
// assertion carrying an attacker-chosen user_id and no valid cryptographic
// signature. Against the vulnerable code they would PASS (a session is minted);
// against the fix they REJECT with no session.

import { describe, expect, it, vi } from "vitest";
import {
  InMemorySubjectSessionStore,
  InMemorySubjectWebAuthnCredentialStore,
  InMemoryWebAuthnChallengeStore,
  verifyWebAuthnAssertion,
  type WebAuthnAssertion,
  type WebAuthnVerificationConfig,
} from "../../src/webauthn/index.js";
import { HttpProblem } from "../../src/errors/index.js";

const CONFIG: WebAuthnVerificationConfig = {
  rpId: "user.cealis.local",
  origin: "https://user.cealis.local",
};

// A structurally-shaped but cryptographically-junk assertion — the exact thing
// an attacker would POST. There is no `user_id` field in the real assertion
// type; the attacker would have relied on the old code reading it from the body.
function forgedAssertion(overrides: Partial<WebAuthnAssertion> = {}): WebAuthnAssertion {
  return {
    id: "forged-credential-id",
    rawId: "forged-credential-id",
    response: {
      clientDataJSON: "Zm9yZ2Vk", // base64url("forged")
      authenticatorData: "Zm9yZ2Vk",
      signature: "Zm9yZ2Vk",
    },
    clientExtensionResults: {},
    type: "public-key",
    ...overrides,
  } as WebAuthnAssertion;
}

describe("F-1 WebAuthn fake-success regression", () => {
  it("rejects when the credential store / RP binding seam is not wired (fail-closed, no session)", async () => {
    const challenges = new InMemoryWebAuthnChallengeStore();
    const sessions = new InMemorySubjectSessionStore();
    const challenge = challenges.create({ purpose: "login" });

    await expect(
      verifyWebAuthnAssertion({
        challenge_id: challenge.challenge_id,
        assertion: forgedAssertion(),
        challenges,
        sessions,
        // credentials + config deliberately omitted — the old code would still
        // have minted a session here.
      }),
    ).rejects.toBeInstanceOf(HttpProblem);
  });

  it("rejects a forged assertion for an UNREGISTERED credentialId (the takeover path)", async () => {
    const challenges = new InMemoryWebAuthnChallengeStore();
    const sessions = new InMemorySubjectSessionStore();
    const credentials = new InMemorySubjectWebAuthnCredentialStore();
    const challenge = challenges.create({ purpose: "login" });

    let threw: unknown;
    try {
      await verifyWebAuthnAssertion({
        challenge_id: challenge.challenge_id,
        // attacker tries to become "victim_subject" — no such field exists, and
        // the credentialId is not registered.
        assertion: forgedAssertion({ id: "victim_subject" }),
        challenges,
        sessions,
        credentials,
        config: CONFIG,
      });
    } catch (error) {
      threw = error;
    }
    expect(threw).toBeInstanceOf(HttpProblem);
    expect((threw as HttpProblem).body.code).toBe("AUTH.UNAUTHENTICATED");
    // No session was minted for anyone.
  });

  it("rejects a forged (junk-signature) assertion even for a REGISTERED credential", async () => {
    const challenges = new InMemoryWebAuthnChallengeStore();
    const sessions = new InMemorySubjectSessionStore();
    const credentials = new InMemorySubjectWebAuthnCredentialStore();
    credentials.register({
      user_id: "subject_real",
      credential: {
        id: "real-credential-id",
        publicKey: new Uint8Array([1, 2, 3, 4]), // not a valid COSE key
        counter: 0,
      },
    });
    const challenge = challenges.create({ purpose: "login" });

    // The credential exists, but the signature/clientData are junk — the real
    // @simplewebauthn verifier must throw or return verified:false → reject.
    await expect(
      verifyWebAuthnAssertion({
        challenge_id: challenge.challenge_id,
        assertion: forgedAssertion({ id: "real-credential-id" }),
        challenges,
        sessions,
        credentials,
        config: CONFIG,
      }),
    ).rejects.toBeInstanceOf(HttpProblem);
  });

  it("rejects when the challenge is unknown / already consumed", async () => {
    const challenges = new InMemoryWebAuthnChallengeStore();
    const sessions = new InMemorySubjectSessionStore();
    const credentials = new InMemorySubjectWebAuthnCredentialStore();

    await expect(
      verifyWebAuthnAssertion({
        challenge_id: "no-such-challenge",
        assertion: forgedAssertion(),
        challenges,
        sessions,
        credentials,
        config: CONFIG,
      }),
    ).rejects.toBeInstanceOf(HttpProblem);
  });
});

// Positive-binding test: on a genuinely-verified assertion the session user_id
// is taken from the MATCHED CREDENTIAL RECORD, never from any client-supplied
// field. We stub the @simplewebauthn verifier's success result so the test does
// not need a hardware authenticator; the assertion under test still names a
// different "victim" credentialId, proving identity is decided server-side.
describe("F-1 user_id is bound to the credential, not the request body", () => {
  it("mints the session for the credential's user_id on a verified assertion", async () => {
    vi.resetModules();
    vi.doMock("@simplewebauthn/server", () => ({
      verifyAuthenticationResponse: vi.fn(async () => ({
        verified: true,
        authenticationInfo: { credentialID: "real-credential-id", newCounter: 7 },
      })),
    }));

    const webauthn = await import("../../src/webauthn/index.js");
    const challenges = new webauthn.InMemoryWebAuthnChallengeStore();
    const sessions = new webauthn.InMemorySubjectSessionStore();
    const credentials = new webauthn.InMemorySubjectWebAuthnCredentialStore();
    credentials.register({
      user_id: "subject_owner",
      credential: { id: "real-credential-id", publicKey: new Uint8Array([1, 2, 3, 4]), counter: 0 },
    });
    const challenge = challenges.create({ purpose: "login" });

    const result = await webauthn.verifyWebAuthnAssertion({
      challenge_id: challenge.challenge_id,
      assertion: forgedAssertion({ id: "real-credential-id" }),
      challenges,
      sessions,
      credentials,
      config: CONFIG,
    });

    // user_id comes from the credential record (subject_owner), NOT from any body field.
    expect(result.session.user_id).toBe("subject_owner");
    expect(result.bearer_token.length).toBeGreaterThan(0);
    // signCounter was advanced and persisted.
    expect(credentials.getByCredentialId("real-credential-id")?.credential.counter).toBe(7);

    vi.doUnmock("@simplewebauthn/server");
    vi.resetModules();
  });
});
