import { request as httpsRequest } from "node:https";
import type { TLSSocket } from "node:tls";
import type { ChainInfo, RandomnessBeacon } from "drand-client";

import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";

export interface DrandEndpoint {
  readonly id: string;
  readonly url: `https://${string}`;
  readonly chainHash: string;
  readonly certificateSha256: string;
  readonly timeoutMs?: number;
}

export interface DrandChainProfile {
  readonly chainHash: string;
  readonly publicKey: Uint8Array;
  readonly periodSeconds: number;
  readonly genesisTime: number;
  readonly tlockCiphersuiteId: string;
  readonly committeeKeyRef: string;
  readonly governanceTimelockRef: string;
}

export interface DrandRoundResult {
  readonly round: bigint;
  readonly signature: Uint8Array;
  readonly chainHash: string;
  readonly publicKey: Uint8Array;
  readonly endpointId: string;
  readonly independentEndpointCount: number;
}

export interface DrandEndpointRoundResponse {
  readonly round: bigint;
  readonly signature: Uint8Array;
  readonly chainHash: string;
  readonly publicKey: Uint8Array;
}

export type DrandRoundFetcher = (
  endpoint: DrandEndpoint,
  round: bigint,
  chain: DrandChainProfile,
) => Promise<DrandEndpointRoundResponse>;

export interface DrandClientConfig {
  readonly endpoints: readonly DrandEndpoint[];
  readonly chain: DrandChainProfile;
  readonly fetchRound?: DrandRoundFetcher;
}

export class DrandClient {
  private readonly endpoints: readonly DrandEndpoint[];
  private readonly chain: DrandChainProfile;
  private readonly fetcher: DrandRoundFetcher;

  constructor(config: DrandClientConfig) {
    if (config.endpoints.length < 2) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE,
        "drand adapter requires at least two configured endpoints",
      );
    }
    for (const endpoint of config.endpoints) {
      assertPinnedHttpsEndpoint(endpoint);
    }
    this.endpoints = Object.freeze([...config.endpoints]);
    this.chain = config.chain;
    this.fetcher = config.fetchRound ?? fetchRoundViaPinnedHttps;
  }

  public getChainProfile(): DrandChainProfile {
    return this.chain;
  }

  public getEndpoints(): readonly DrandEndpoint[] {
    return this.endpoints;
  }

  public async fetchRound(targetRound: bigint): Promise<DrandRoundResult> {
    const successes: DrandEndpointRoundResponse[] = [];
    let firstEndpointId = "";
    const failures: string[] = [];

    for (const endpoint of this.endpoints) {
      try {
        const response = await this.fetcher(endpoint, targetRound, this.chain);
        assertRoundMatches(targetRound, this.chain, response);
        successes.push(response);
        if (firstEndpointId.length === 0) firstEndpointId = endpoint.id;
      } catch (err) {
        if (
          err instanceof CustodyError &&
          err.code !== CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE
        ) {
          throw err;
        }
        failures.push(`${endpoint.id}:${errorCode(err)}`);
      }
    }

    if (successes.length === 0) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE,
        "no configured drand endpoint returned the target round",
        { metadata: { endpoints: this.endpoints.length, failures: failures.join(",") } },
      );
    }

    const first = successes[0];
    if (first === undefined) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE,
        "internal drand fetch invariant failed",
      );
    }
    for (const response of successes.slice(1)) {
      if (!bytesEqual(first.signature, response.signature)) {
        throw new CustodyError(
          CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_SIG_INVALID,
          "independent drand endpoints returned different signatures",
          { metadata: { round: targetRound } },
        );
      }
    }

    return {
      round: first.round,
      signature: new Uint8Array(first.signature),
      chainHash: first.chainHash,
      publicKey: new Uint8Array(first.publicKey),
      endpointId: firstEndpointId,
      independentEndpointCount: successes.length,
    };
  }
}

export async function fetchRoundViaPinnedHttps(
  endpoint: DrandEndpoint,
  round: bigint,
  chain: DrandChainProfile,
): Promise<DrandEndpointRoundResponse> {
  const beaconUrl = new URL(
    `${encodeURIComponent(endpoint.chainHash)}/public/${round.toString()}`,
    endpoint.url.endsWith("/") ? endpoint.url : `${endpoint.url}/`,
  );
  const beacon = await fetchJsonPinned<RandomnessBeacon>(
    beaconUrl,
    endpoint.certificateSha256,
    endpoint.timeoutMs ?? 5_000,
  );
  return {
    round: BigInt(beacon.round),
    signature: hexToBytes(beacon.signature),
    chainHash: chain.chainHash,
    publicKey: chain.publicKey,
  };
}

export async function fetchChainInfoViaPinnedHttps(
  endpoint: DrandEndpoint,
): Promise<ChainInfo> {
  const infoUrl = new URL(
    `${encodeURIComponent(endpoint.chainHash)}/info`,
    endpoint.url.endsWith("/") ? endpoint.url : `${endpoint.url}/`,
  );
  return fetchJsonPinned<ChainInfo>(
    infoUrl,
    endpoint.certificateSha256,
    endpoint.timeoutMs ?? 5_000,
  );
}

function assertPinnedHttpsEndpoint(endpoint: DrandEndpoint): void {
  const url = new URL(endpoint.url);
  if (url.protocol !== "https:") {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE,
      `drand endpoint ${endpoint.id} must use HTTPS`,
    );
  }
  if (normalizePin(endpoint.certificateSha256).length !== 64) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE,
      `drand endpoint ${endpoint.id} is missing a sha256 certificate pin`,
    );
  }
}

function assertRoundMatches(
  targetRound: bigint,
  chain: DrandChainProfile,
  response: DrandEndpointRoundResponse,
): void {
  if (response.round !== targetRound) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ROUND_MISMATCH,
      "drand endpoint returned a different round",
      { metadata: { expectedRound: targetRound, returnedRound: response.round } },
    );
  }
  if (response.chainHash !== chain.chainHash) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "drand endpoint returned a different chain hash",
    );
  }
  if (!bytesEqual(response.publicKey, chain.publicKey)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH,
      "drand endpoint returned a different public key",
    );
  }
  if (response.signature.length !== 96) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_SIG_INVALID,
      `drand signature must be 96 bytes, got ${response.signature.length}`,
    );
  }
}

function fetchJsonPinned<T>(
  url: URL,
  certificateSha256: string,
  timeoutMs: number,
): Promise<T> {
  const expectedPin = normalizePin(certificateSha256);
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      url,
      {
        method: "GET",
        minVersion: "TLSv1.3",
        timeout: timeoutMs,
        headers: { accept: "application/json" },
      },
      (res) => {
        try {
          const cert = (res.socket as TLSSocket).getPeerCertificate();
          const actual = normalizePin(cert.fingerprint256 ?? "");
          if (actual !== expectedPin) {
            reject(
              new CustodyError(
                CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE,
                "drand endpoint certificate pin mismatch",
              ),
            );
            res.resume();
            return;
          }
        } catch (err) {
          reject(err);
          res.resume();
          return;
        }

        if (res.statusCode === undefined || res.statusCode < 200 || res.statusCode >= 300) {
          reject(
            new CustodyError(
              CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE,
              `drand endpoint HTTP status ${res.statusCode ?? "unknown"}`,
            ),
          );
          res.resume();
          return;
        }

        const chunks: Uint8Array[] = [];
        res.on("data", (chunk: Uint8Array) => chunks.push(new Uint8Array(chunk)));
        res.on("end", () => {
          try {
            const body = Buffer.concat(chunks).toString("utf8");
            resolve(JSON.parse(body) as T);
          } catch (err) {
            reject(err);
          }
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(
        new CustodyError(
          CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE,
          "drand endpoint timeout",
        ),
      );
    });
    req.on("error", reject);
    req.end();
  });
}

function normalizePin(pin: string): string {
  return pin
    .replace(/^sha256\//i, "")
    .replace(/:/g, "")
    .trim()
    .toLowerCase();
}

function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_SIG_INVALID,
      "drand endpoint returned odd-length hex",
    );
  }
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function errorCode(err: unknown): string {
  if (err instanceof CustodyError) return err.code;
  if (err instanceof Error) return err.name;
  return "unknown";
}
