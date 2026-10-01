import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";
import { SigmaBuffer } from "../redaction/sigma-buffer.js";
import { safeStringify } from "../redaction/log-sanitize.js";
import { canonicalizeAcc, type JsonValue } from "./acc-canonicalize.js";
import { litDcapQuoteDigest, type LitDcapQuoteInput } from "./dcap-quote.js";
import { verifyLitChannelIdentity } from "./channel-identity.js";

const require = createRequire(import.meta.url);

export interface LitChipotleClientConfig {
  readonly baseUrl: string;
  readonly apiVersion: string;
  readonly certificatePinSha256: string;
  readonly mtlsClientCertificateSha256?: string;
  readonly transport?: LitChipotleTransport;
  readonly apiVersionFixturePath?: string;
}

export interface LitChipotleTransport {
  requestSignature(input: LitChipotleSignatureRequest): Promise<LitChipotleRawResponse>;
  health?(): Promise<LitChipotleHealthResponse>;
}

export interface LitChipotleSignatureRequest {
  readonly canonicalAccBytes: Uint8Array;
  readonly authorizationId: string;
  readonly hCommit: string;
  readonly blockHash: string;
  readonly idempotencyKey: string;
}

export interface LitChipotleRawResponse {
  readonly sigma: Uint8Array | string;
  readonly dcapQuote: Uint8Array | string | Record<string, unknown>;
  readonly assignmentId: string;
  readonly observedCertificateSha256?: string;
  readonly observedTeeChannelId?: string;
  readonly apiVersion?: string;
}

export interface LitChipotleSignatureResponse {
  readonly sigma: SigmaBuffer;
  readonly dcapQuote: SigmaBuffer;
  readonly assignmentId: string;
  readonly quoteDigest: string;
  readonly receivedAt: bigint;
  readonly apiVersion: string;
}

export interface LitChipotleHealthResponse {
  readonly ok: boolean;
  readonly latencyMs: number;
  readonly registryHead?: string | number | bigint;
  readonly lastRefusalOrDeprecationSignal?: string;
}

export interface LitApiVersionArtifact {
  readonly vendorConfirmation: "VENDOR_CONFIRMATION_LIT_CORE_API";
  readonly baseUrl: string;
  readonly apiVersion: string;
  readonly litNodeClientVersion: string;
  readonly contractsSdkVersion: string;
  readonly certificatePinSha256: string;
  readonly capturedAt: string;
}

export class LitChipotleClient {
  public readonly config: LitChipotleClientConfig;
  public readonly versionArtifact: LitApiVersionArtifact;

  constructor(config: LitChipotleClientConfig) {
    verifyLitChannelIdentity({
      endpointUrl: config.baseUrl,
      certificatePinSha256: config.certificatePinSha256,
      mtlsClientCertificateSha256: config.mtlsClientCertificateSha256,
    });
    if (config.transport === undefined) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
        "Lit Chipotle client requires an explicit low-level transport with cert pinning/mTLS support",
      );
    }
    this.config = Object.freeze({ ...config });
    this.versionArtifact = Object.freeze({
      vendorConfirmation: "VENDOR_CONFIRMATION_LIT_CORE_API",
      baseUrl: config.baseUrl,
      apiVersion: config.apiVersion,
      litNodeClientVersion: packageVersion("@lit-protocol/lit-node-client"),
      contractsSdkVersion: packageVersion("@lit-protocol/contracts-sdk"),
      certificatePinSha256: config.certificatePinSha256,
      capturedAt: new Date().toISOString(),
    });
    if (config.apiVersionFixturePath !== undefined) {
      writeFileSync(
        config.apiVersionFixturePath,
        `${safeStringify(this.versionArtifact, 2)}\n`,
        { encoding: "utf8" },
      );
    }
  }

  public async requestSigma(input: LitChipotleSignatureRequest): Promise<LitChipotleSignatureResponse> {
    let response: LitChipotleRawResponse;
    try {
      response = await this.config.transport!.requestSignature(input);
    } catch (err) {
      if (err instanceof CustodyError) throw err;
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
        "Lit Chipotle request failed",
        { cause: err },
      );
    }
    if (response.apiVersion !== undefined && response.apiVersion !== this.config.apiVersion) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
        "Lit Chipotle API version drift",
      );
    }
    verifyLitChannelIdentity({
      endpointUrl: this.config.baseUrl,
      certificatePinSha256: this.config.certificatePinSha256,
      observedCertificateSha256: response.observedCertificateSha256,
      observedTeeChannelId: response.observedTeeChannelId,
    });
    const sigma = new SigmaBuffer(bytesFromResponse(response.sigma));
    const quoteBytes = quoteBytesFromResponse(response.dcapQuote);
    const dcapQuote = new SigmaBuffer(quoteBytes);
    return {
      sigma,
      dcapQuote,
      assignmentId: response.assignmentId,
      quoteDigest: litDcapQuoteDigest(quoteBytes),
      receivedAt: BigInt(Date.now()),
      apiVersion: this.config.apiVersion,
    };
  }

  public async health(): Promise<LitChipotleHealthResponse> {
    if (this.config.transport?.health === undefined) {
      return { ok: true, latencyMs: 0 };
    }
    return this.config.transport.health();
  }
}

export function assertChipotleEvidenceSurface(candidate: unknown): void {
  if (typeof candidate !== "object" || candidate === null) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
      "Lit SDK surface unavailable",
    );
  }
  const obj = candidate as Record<string, unknown>;
  if (typeof obj.decrypt === "function" && typeof obj.executeJs !== "function") {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
      "Lit SDK exposes decrypt-only surface; sigma and quote evidence are not separately available",
    );
  }
}

export function buildLitIdempotencyKey(input: {
  readonly authorizationId: string;
  readonly hCommit: string;
  readonly authorizationBlock: bigint;
  readonly assignedTeeId: string;
}): string {
  return [
    input.authorizationId.toLowerCase(),
    input.hCommit.toLowerCase(),
    input.authorizationBlock.toString(),
    input.assignedTeeId.toLowerCase(),
  ].join(":");
}

function packageVersion(name: string): string {
  const pkg = require(`${name}/package.json`) as { version?: unknown };
  if (typeof pkg.version !== "string") throw new Error(`missing version in ${name}/package.json`);
  return pkg.version;
}

function bytesFromResponse(value: Uint8Array | string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function quoteBytesFromResponse(value: LitDcapQuoteInput): Uint8Array {
  if (value instanceof SigmaBuffer) return value.unwrap();
  if (value instanceof Uint8Array) return value;
  if (typeof value === "string") return new TextEncoder().encode(value);
  return canonicalizeAcc(value as JsonValue);
}

export function apiVersionFixtureBytes(artifact: LitApiVersionArtifact): Uint8Array {
  return new TextEncoder().encode(`${safeStringify(artifact, 2)}\n`);
}
