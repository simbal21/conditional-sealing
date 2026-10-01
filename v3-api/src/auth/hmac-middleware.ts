import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { buildCanonicalRequest } from "./canonical-request.js";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import type { ApiScope } from "../types/scopes.js";
import {
  HMAC_REPLAY_WINDOW_SECONDS,
  type PartnerPrincipal,
} from "../types/auth.js";
import type { NonceStore } from "./nonce-store.js";

export interface PartnerCredentialRecord {
  readonly partner_id: string;
  readonly key_id: string;
  readonly signing_secret: Uint8Array | string;
  readonly scopes: readonly ApiScope[];
  readonly revoked_at?: string | null;
}

export interface VerifyPartnerHmacInput {
  readonly method: "GET" | "POST" | "DELETE";
  readonly pathWithQuery: string;
  readonly rawRequestBody: Uint8Array;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly lookupCredential: (keyId: string) => PartnerCredentialRecord | undefined | Promise<PartnerCredentialRecord | undefined>;
  readonly nonceStore: NonceStore;
  readonly now?: Date;
  readonly correlationId?: string;
}

const textEncoder = new TextEncoder();

export async function verifyPartnerHmac(input: VerifyPartnerHmacInput): Promise<PartnerPrincipal> {
  const correlationId = input.correlationId ?? "auth";
  const keyId = getHeader(input.headers, "x-cealis-key-id");
  const timestamp = getHeader(input.headers, "x-cealis-timestamp");
  const nonce = getHeader(input.headers, "x-cealis-nonce");
  const signature = getHeader(input.headers, "x-cealis-signature");
  if (!keyId || !timestamp || !nonce || !signature) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
        detail: "Partner HMAC headers are incomplete.",
      }),
    );
  }

  assertReplayWindow(timestamp, input.now ?? new Date(), correlationId);
  const credential = await input.lookupCredential(keyId);
  if (!credential || credential.revoked_at) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
        detail: "Partner credential is missing or revoked.",
      }),
    );
  }
  const noncePassed = await input.nonceStore.consume({
    keyId,
    nonce,
    nowMs: (input.now ?? new Date()).getTime(),
  });
  if (!noncePassed) {
    throw new HttpProblem(
      problemFromCode("AUTH_REPLAY", correlationId, {
        detail: "Partner nonce was already used inside the 24h window.",
      }),
    );
  }

  const canonical = buildCanonicalRequest({
    method: input.method,
    pathWithQuery: input.pathWithQuery,
    timestamp,
    nonce,
    rawRequestBody: input.rawRequestBody,
  });
  const expected = `sha256=${bytesToHex(hmac(sha256, secretBytes(credential.signing_secret), canonical))}`;
  if (!constantTimeAsciiEqual(expected, signature)) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
        detail: "Partner request signature did not match canonical request.",
      }),
    );
  }

  return {
    partner_id: credential.partner_id,
    key_id: credential.key_id,
    scopes: new Set(credential.scopes),
  };
}

export function createPartnerHmacPreHandler(options: {
  readonly lookupCredential: VerifyPartnerHmacInput["lookupCredential"];
  readonly nonceStore: NonceStore;
  readonly now?: () => Date;
}): preHandlerHookHandler {
  return (request: FastifyRequest, _reply: FastifyReply, done): void => {
    const rawRequestBody = rawBodyFromRequest(request);
    void verifyPartnerHmac({
      method: methodFromRequest(request.method),
      pathWithQuery: request.url,
      rawRequestBody,
      headers: request.headers as Record<string, string | string[] | undefined>,
      lookupCredential: options.lookupCredential,
      nonceStore: options.nonceStore,
      now: options.now?.() ?? new Date(),
      correlationId: request.id,
    })
      .then((principal) => {
        request.partnerPrincipal = principal;
        done();
      })
      .catch((error: unknown) => done(error as Error));
  };
}

export function signPartnerRequest(input: {
  readonly method: "GET" | "POST" | "DELETE";
  readonly pathWithQuery: string;
  readonly rawRequestBody: Uint8Array;
  readonly keyId: string;
  readonly signingSecret: Uint8Array | string;
  readonly timestamp: string;
  readonly nonce: string;
}): Record<string, string> {
  const canonical = buildCanonicalRequest({
    method: input.method,
    pathWithQuery: input.pathWithQuery,
    timestamp: input.timestamp,
    nonce: input.nonce,
    rawRequestBody: input.rawRequestBody,
  });
  return {
    "x-cealis-key-id": input.keyId,
    "x-cealis-timestamp": input.timestamp,
    "x-cealis-nonce": input.nonce,
    "x-cealis-signature": `sha256=${bytesToHex(hmac(sha256, secretBytes(input.signingSecret), canonical))}`,
  };
}

export function rawBodyFromRequest(request: FastifyRequest): Uint8Array {
  const maybeRaw = (request as { rawBodyBytes?: Uint8Array }).rawBodyBytes;
  if (maybeRaw) return maybeRaw;
  if (request.body === undefined || request.body === null) return new Uint8Array();
  return textEncoder.encode(JSON.stringify(request.body));
}

function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0];
  return value;
}

function assertReplayWindow(timestamp: string, now: Date, correlationId: string): void {
  if (!/^\d+$/.test(timestamp)) {
    throw new HttpProblem(
      problemFromCode("AUTH_REPLAY", correlationId, {
        detail: "Partner timestamp must be unix seconds.",
      }),
    );
  }
  const tsMs = Number(timestamp) * 1000;
  if (!Number.isFinite(tsMs) || Math.abs(now.getTime() - tsMs) > HMAC_REPLAY_WINDOW_SECONDS * 1000) {
    throw new HttpProblem(
      problemFromCode("AUTH_REPLAY", correlationId, {
        detail: "Partner timestamp is outside the 300s replay window.",
      }),
    );
  }
}

function methodFromRequest(method: string): "GET" | "POST" | "DELETE" {
  if (method === "GET" || method === "POST" || method === "DELETE") return method;
  return "GET";
}

function secretBytes(secret: Uint8Array | string): Uint8Array {
  if (secret instanceof Uint8Array) return secret;
  if (/^0x[0-9a-fA-F]+$/.test(secret) && secret.length % 2 === 0) {
    return hexToBytes(secret.slice(2));
  }
  return textEncoder.encode(secret);
}

function constantTimeAsciiEqual(left: string, right: string): boolean {
  const a = textEncoder.encode(left);
  const b = textEncoder.encode(right);
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let index = 0; index < len; index += 1) {
    diff |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return diff === 0;
}
