// G4 Phase 1 HTTPS+mTLS transport — concrete implementation of G4Phase1DaemonTransport.
//
// Calls the Railway-hosted (or future Nitro Enclave) G4 daemon over HTTPS with mutual
// TLS authentication. The orchestrator's client cert MUST match the SHA-256 fingerprint
// the daemon pins (its G4_PHASE1_CLIENT_FINGERPRINT256 env var). Server cert is verified
// against the CA used to sign it (same CA as the client cert in v0.1 dev-local; pilot
// will use a properly-issued cert from a fronted CA).
//
// Wire format (matches v3-custody/g4-phase1/server/main.ts /sign handler):
//   POST /sign  Content-Type: application/json
//   Request: {
//     requestId, presign, timestamp (string), binaryHash (0x-hex),
//     blockHash (0x-hex), authorizationId (0x-hex), hCommit (0x-hex),
//     kemPubkey (0x-hex)
//   }
//   Response: {
//     requestId, authorizationId, hCommit, blockHash,
//     timestamp (string), sigma (0x-hex), kemProof
//   }
//
// Closes G4Phase1AdapterConfig.transport = unsupportedNetworkTransport() throw path.

import { Agent, request as httpsRequest } from "node:https";
import { randomUUID } from "node:crypto";
import type { Hex32 } from "@cealis/v3-crypto";
import type { RequestSigmaInput } from "../adapters/gate-adapter.js";
import type { G4Phase1DaemonTransport, G4Phase1RequestExtras } from "./adapter.js";
import type { G4Phase1KemDecapProof } from "./kem-binding-proof.js";
import { CustodyError, CUSTODY_ERROR_CODES } from "../errors.js";

/**
 * Connection config for the HTTPS+mTLS transport. All cert material is passed as bytes
 * (caller reads from disk or KMS); this module never touches the filesystem.
 */
export interface MtlsHttpsTransportConfig {
  /** Daemon endpoint URL — e.g., `new URL("https://g4-daemon.example.com")`. */
  readonly endpoint: URL;
  /** PEM bytes of the orchestrator's client cert (the daemon pins its SHA-256). */
  readonly clientCertPem: Buffer;
  /** PEM bytes of the orchestrator's client private key. */
  readonly clientKeyPem: Buffer;
  /** PEM bytes of the CA that signed the daemon's server cert. */
  readonly caPem: Buffer;
  /** Optional: override Server Name Indication (defaults to endpoint.hostname). */
  readonly servername?: string;
  /** Per-request timeout in ms. Default 10000. The daemon's signing is sub-ms; this
   *  budget covers RTT + Railway routing variance. */
  readonly requestTimeoutMs?: number;
  /** Keep-alive agent reuse — default true. Phase-1 daemons under load benefit from
   *  warm TLS connections. */
  readonly keepAlive?: boolean;
}

/** Concrete HTTPS+mTLS transport. Reusable across requests (TLS session resumption via
 *  keep-alive agent). One instance per daemon endpoint. */
export class MtlsHttpsTransport implements G4Phase1DaemonTransport {
  private readonly agent: Agent;
  private readonly endpoint: URL;
  private readonly servername: string;
  private readonly timeoutMs: number;

  constructor(private readonly cfg: MtlsHttpsTransportConfig) {
    this.endpoint = cfg.endpoint;
    this.servername = cfg.servername ?? cfg.endpoint.hostname;
    this.timeoutMs = cfg.requestTimeoutMs ?? 10_000;
    this.agent = new Agent({
      keepAlive: cfg.keepAlive ?? true,
      cert: cfg.clientCertPem,
      key: cfg.clientKeyPem,
      ca: cfg.caPem,
      // checkServerIdentity defaults to verifying CN/SAN matches hostname; do NOT
      // override unless we're using IP-based pinning (which would conflict with the
      // daemon's CN=g4-phase1.local in dev-local certs — for that case set
      // `servername` to "g4-phase1.local" via the config).
    });
  }

  public async sign(input: RequestSigmaInput<G4Phase1RequestExtras>): Promise<{
    readonly sigma: Uint8Array;
    readonly kemProof?: G4Phase1KemDecapProof;
    readonly metadata?: Readonly<Record<string, string | number | bigint | Hex32>>;
  }> {
    const body = {
      requestId: randomUUID(),
      // presign: the daemon's assertServerPresignChecklist re-validates these fields.
      // We send the same data the caller assembled; if the daemon's recheck fails it
      // returns 400 and we throw a typed CustodyError.
      presign: {
        authorizationId: input.authorizationId,
        hCommit: input.hCommit,
        authorizationBlock: input.authorizationBlock.toString(),
        blockHash: input.blockHash,
        currentBlock: input.extras.currentBlock.toString(),
        finalityDepth: input.extras.finalityDepth.toString(),
        challengeWindowClosed: input.extras.challengeWindowClosed,
      },
      timestamp: input.extras.timestamp.toString(),
      binaryHash: input.extras.binaryHash,
      blockHash: input.blockHash,
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      // kemPubkey on the wire is the authority pubkey bytes (Ed25519 32-byte). The
      // daemon's produceKemDecapProof uses it to derive a binding proof; the
      // orchestrator-side adapter then verifies the proof against the registered
      // G4 KEM pubkey from registryReader.
      kemPubkey: bytesToHex(input.extras.authorityPubkey),
    };

    const responseBody = await this.postJson("/sign", body);
    const parsed = parseSignResponse(responseBody);

    return {
      sigma: parsed.sigma,
      kemProof: parsed.kemProof,
      metadata: {
        endpoint: this.endpoint.origin,
        phase: 1,
        requestId: body.requestId,
        responseRequestId: parsed.requestId,
      },
    };
  }

  /** Internal: POST JSON to a daemon path; throws CustodyError on non-200 or transport
   *  failure. Body is fully buffered (daemon responses are small — sigma + kemProof,
   *  <1KB typical). */
  private postJson(path: string, body: unknown): Promise<string> {
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    return new Promise<string>((resolve, reject) => {
      const req = httpsRequest(
        {
          method: "POST",
          host: this.endpoint.hostname,
          port: this.endpoint.port === "" ? 443 : Number.parseInt(this.endpoint.port, 10),
          path,
          servername: this.servername,
          agent: this.agent,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": payload.length.toString(),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            const buf = Buffer.concat(chunks).toString("utf8");
            if (res.statusCode !== 200) {
              reject(
                new CustodyError(
                  CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
                  `G4 Phase 1 daemon returned ${res.statusCode}: ${truncate(buf, 200)}`,
                ),
              );
              return;
            }
            resolve(buf);
          });
          res.on("error", (e) =>
            reject(
              new CustodyError(
                CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
                `G4 Phase 1 daemon response error: ${e.message}`,
              ),
            ),
          );
        },
      );
      req.setTimeout(this.timeoutMs, () => {
        req.destroy(
          new CustodyError(
            CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
            `G4 Phase 1 daemon request timed out after ${this.timeoutMs}ms`,
          ),
        );
      });
      req.on("error", (e) =>
        reject(
          e instanceof CustodyError
            ? e
            : new CustodyError(
                CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
                `G4 Phase 1 daemon request failed: ${e.message}`,
              ),
        ),
      );
      req.end(payload);
    });
  }

  /** Releases the keep-alive sockets. Call at orchestrator shutdown. */
  public close(): void {
    this.agent.destroy();
  }
}

interface ParsedSignResponse {
  readonly requestId: string;
  readonly sigma: Uint8Array;
  readonly kemProof?: G4Phase1KemDecapProof;
}

function parseSignResponse(raw: string): ParsedSignResponse {
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
      `G4 Phase 1 daemon returned non-JSON body: ${truncate(raw, 100)}`,
    );
  }
  if (typeof json.sigma !== "string" || !json.sigma.startsWith("0x")) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
      `G4 Phase 1 daemon response missing sigma`,
    );
  }
  return {
    requestId: typeof json.requestId === "string" ? json.requestId : "",
    sigma: hexToBytes(json.sigma),
    kemProof: json.kemProof as G4Phase1KemDecapProof | undefined,
  };
}

function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "0x";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n) + "…";
}
