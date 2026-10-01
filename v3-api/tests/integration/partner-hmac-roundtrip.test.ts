import { describe, expect, it } from "vitest";
import { InMemoryNonceStore, extractBearerToken, signPartnerRequest, verifyPartnerHmac } from "../../src/auth/index.js";
import { HttpProblem } from "../../src/errors/index.js";
import type { ApiScope } from "../../src/types/index.js";

describe("partner HMAC roundtrip", () => {
  it("signs via the Phase A canonical request and verifies a partner principal", async () => {
    const now = new Date("2026-05-11T12:00:00.000Z");
    const timestamp = Math.floor(now.getTime() / 1000).toString();
    const body = new TextEncoder().encode('{"pda_id":"pda_demo"}');
    const scopes: ApiScope[] = ["pda:read", "reveal:read"];
    const headers = signPartnerRequest({
      method: "POST",
      pathWithQuery: "/v1/partners/me/onboarding-links",
      rawRequestBody: body,
      keyId: "key_demo",
      signingSecret: "secret_demo",
      timestamp,
      nonce: "nonce_demo",
    });
    const principal = await verifyPartnerHmac({
      method: "POST",
      pathWithQuery: "/v1/partners/me/onboarding-links",
      rawRequestBody: body,
      headers,
      nonceStore: new InMemoryNonceStore(),
      now,
      lookupCredential: () => ({
        partner_id: "partner_demo",
        key_id: "key_demo",
        signing_secret: "secret_demo",
        scopes,
      }),
    });
    expect(principal.partner_id).toBe("partner_demo");
    expect(principal.scopes.has("reveal:read")).toBe(true);
  });

  it("rejects missing headers, stale timestamps, bad signatures, and nonce replay", async () => {
    const now = new Date("2026-05-11T12:00:00.000Z");
    const nonceStore = new InMemoryNonceStore();
    const lookupCredential = () => ({
      partner_id: "partner_demo",
      key_id: "key_demo",
      signing_secret: "secret_demo",
      scopes: ["pda:read"] satisfies ApiScope[],
    });
    await expect(
      verifyPartnerHmac({
        method: "GET",
        pathWithQuery: "/v1/partners/me/pdas",
        rawRequestBody: new Uint8Array(),
        headers: {},
        nonceStore,
        now,
        lookupCredential,
      }),
    ).rejects.toBeInstanceOf(HttpProblem);

    const staleHeaders = signPartnerRequest({
      method: "GET",
      pathWithQuery: "/v1/partners/me/pdas",
      rawRequestBody: new Uint8Array(),
      keyId: "key_demo",
      signingSecret: "secret_demo",
      timestamp: "1",
      nonce: "nonce_stale",
    });
    await expect(
      verifyPartnerHmac({
        method: "GET",
        pathWithQuery: "/v1/partners/me/pdas",
        rawRequestBody: new Uint8Array(),
        headers: staleHeaders,
        nonceStore,
        now,
        lookupCredential,
      }),
    ).rejects.toMatchObject({ body: expect.objectContaining({ code: "AUTH.REPLAY" }) });

    const goodHeaders = signPartnerRequest({
      method: "GET",
      pathWithQuery: "/v1/partners/me/pdas",
      rawRequestBody: new Uint8Array(),
      keyId: "key_demo",
      signingSecret: "secret_demo",
      timestamp: Math.floor(now.getTime() / 1000).toString(),
      nonce: "nonce_once",
    });
    await expect(
      verifyPartnerHmac({
        method: "GET",
        pathWithQuery: "/v1/partners/me/pdas",
        rawRequestBody: new Uint8Array(),
        headers: { ...goodHeaders, "x-cealis-signature": "sha256=00" },
        nonceStore: new InMemoryNonceStore(),
        now,
        lookupCredential,
      }),
    ).rejects.toMatchObject({ body: expect.objectContaining({ code: "AUTH.UNAUTHENTICATED" }) });
    await expect(
      verifyPartnerHmac({
        method: "GET",
        pathWithQuery: "/v1/partners/me/pdas",
        rawRequestBody: new Uint8Array(),
        headers: goodHeaders,
        nonceStore,
        now,
        lookupCredential,
      }),
    ).resolves.toMatchObject({ partner_id: "partner_demo" });
    await expect(
      verifyPartnerHmac({
        method: "GET",
        pathWithQuery: "/v1/partners/me/pdas",
        rawRequestBody: new Uint8Array(),
        headers: goodHeaders,
        nonceStore,
        now,
        lookupCredential,
      }),
    ).rejects.toMatchObject({ body: expect.objectContaining({ code: "AUTH.REPLAY" }) });
    expect(extractBearerToken({ authorization: "Bearer subject_token" })).toBe("subject_token");
    expect(extractBearerToken({ authorization: "Basic nope" })).toBeUndefined();
  });
});
