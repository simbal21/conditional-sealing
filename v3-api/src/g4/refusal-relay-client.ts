// G4 refusal-relay client — orchestrator-side composition of:
//   (1) HTTPS+mTLS POST /refuse to the deployed G4 Phase 1 daemon
//   (2) verifyRefusalClaim() byte-check against the daemon's authority pubkey
//
// This is the orchestrator's defense-in-depth boundary: a network-MitM-modified /refuse
// response (the attacker swaps the canonicalBytes or sig) is caught BEFORE the
// orchestrator submits to G4RefusalRegistry on-chain. The daemon's audit-grade signed
// claim infrastructure (a2ebf11 daemon-side, 8010752 verifier-side) only provides
// audit assurance if the orchestrator actually verifies before chain-write — this
// file is the wiring that makes that integration real.
//
// FLOW (a refusal end-to-end):
//   1. Orchestrator: build refusal request (authorizationId, hCommit, reasonCode, …).
//   2. Orchestrator: relay-client.relayRefusal(req) → HTTPS POST to daemon /refuse.
//   3. Daemon: signs canonical-bytes with Ed25519 authority key, returns {refusalClaim, mode, signed, txHash}.
//   4. Relay-client: parses response, calls verifyRefusalClaim(claim, authorityPubkey).
//   5. If verify fails → throw RefusalRelayError (REJECTED — orchestrator MUST NOT
//      submit a refusal to chain without a verified daemon-signed claim).
//   6. If verify passes → return {claim, daemon_mode, parsed} for the orchestrator's
//      chain-submit step. The chain-submit (G4RefusalRegistry write via OPERATOR_ROLE)
//      is a SEPARATE step that this client does NOT perform. Separation of concerns:
//      relay-client = network + verify; chain-submit-client = transaction + receipt.
//
// SCOPE: parent-territory (v3-api/src/g4/), NOT in workers-1/2/3/4 owned scopes.
// Worker-3 owns v3-custody C1 / B2 cluster. This client lives in v3-api and imports
// the verifier FROM v3-custody (proper layering — orchestrator depends on custody SDK).

import type { IncomingMessage } from "node:http";
import { Agent, request as httpsRequest } from "node:https";
import {
  refusalClaimHexToBytes,
  verifyRefusalClaim,
  type RefusalClaimVerifyErrorCode,
  type ParsedRefusalClaim,
} from "@cealis/v3-custody";

/** Connection + verifier config for the relay client. All bytes-in / no filesystem. */
export interface RefusalRelayClientConfig {
  /** Daemon endpoint URL — e.g., `new URL("https://g4-daemon.example.com")`. */
  readonly endpoint: URL;
  /** PEM bytes of the orchestrator's client cert (the daemon pins SHA-256). */
  readonly clientCertPem: Buffer;
  /** PEM bytes of the orchestrator's client private key. */
  readonly clientKeyPem: Buffer;
  /** PEM bytes of the CA that signed the daemon's server cert. */
  readonly caPem: Buffer;
  /** Raw 32-byte Ed25519 authority pubkey for the daemon. Caller obtains from
   *  G4AuthorityRegistry.sol read OR from known dev-local config. */
  readonly authorityPubkey: Uint8Array;
  /** Optional: SNI override (defaults to endpoint.hostname). dev-local certs use
   *  CN=g4-phase1.local, so callers hitting 127.0.0.1 should set this to
   *  "g4-phase1.local". */
  readonly servername?: string;
  /** Per-request timeout in ms. Default 10000. */
  readonly requestTimeoutMs?: number;
  /** Keep-alive — default true. */
  readonly keepAlive?: boolean;
}

/** What the orchestrator gets back after a successful relay + verify. */
export interface VerifiedRefusal {
  /** The daemon's signed claim envelope (canonical bytes + Ed25519 sig + domain label). */
  readonly claim: {
    readonly canonicalBytes: string;
    readonly ed25519Sig: string;
    readonly domainLabel: string;
  };
  /** Decoded fields from the canonical bytes — same shape verifyRefusalClaim returns. */
  readonly parsed: ParsedRefusalClaim;
  /** The daemon's response mode envelope (e.g., "relay-claim-only"). */
  readonly daemonMode: string;
  /** Daemon's reported txHash (zero in relay-claim-only mode; orchestrator submits to
   *  chain next as a separate step). */
  readonly daemonReportedTxHash: string;
  /** True if the response encoded an encrypted-reason blob (Art.17/18 cases). */
  readonly encryptedBlobHash?: string;
}

/** Error codes the relay client can return. Composed of verifier codes + transport codes. */
export type RefusalRelayErrorCode =
  | "ERR_RELAY_HTTP_STATUS"
  | "ERR_RELAY_RESPONSE_PARSE"
  | "ERR_RELAY_RESPONSE_MISSING_CLAIM"
  | "ERR_RELAY_TIMEOUT"
  | "ERR_RELAY_NETWORK"
  | "ERR_RELAY_CLAIM_VERIFY_FAIL"
  | RefusalClaimVerifyErrorCode;

export class RefusalRelayError extends Error {
  constructor(
    public readonly code: RefusalRelayErrorCode,
    message: string,
    public readonly httpStatus?: number,
    public readonly daemonError?: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "RefusalRelayError";
  }
}

/** Refusal request body shape — matches what the daemon's main.ts /refuse handler reads. */
export interface RelayRefusalInput {
  readonly authorizationId: string; // 0x-hex 32 bytes
  readonly hCommit: string; // 0x-hex 32 bytes
  readonly reasonCode: number; // 0x01..0x0A
  readonly proofRef: string; // 0x-hex 32 bytes (or zeros for non-public reasons)
  /** Hex of plaintext reason payload (Art.17/18 only). Daemon encrypts + hashes;
   *  encryptedBlobHash returned in VerifiedRefusal.encryptedBlobHash. */
  readonly reasonPlaintextHex?: string;
  /** Unix-seconds timestamp the claim binds to. Optional — daemon defaults to its own
   *  Date.now() if not provided. Caller-supplied recommended for audit-replay-determinism. */
  readonly timestamp?: bigint;
}

/**
 * Composes mTLS HTTPS POST /refuse + verifyRefusalClaim. Throws RefusalRelayError on
 * any failure (transport, parse, verify). The orchestrator's chain-submit step gates
 * on a successful return — never submits unverified.
 */
export class RefusalRelayClient {
  private readonly agent: Agent;
  private readonly endpoint: URL;
  private readonly servername: string;
  private readonly timeoutMs: number;
  private readonly authorityPubkey: Uint8Array;

  constructor(cfg: RefusalRelayClientConfig) {
    this.endpoint = cfg.endpoint;
    this.servername = cfg.servername ?? cfg.endpoint.hostname;
    this.timeoutMs = cfg.requestTimeoutMs ?? 10_000;
    if (cfg.authorityPubkey.length !== 32) {
      throw new Error(
        `RefusalRelayClient: authorityPubkey must be 32 raw Ed25519 bytes, got ${cfg.authorityPubkey.length}`,
      );
    }
    this.authorityPubkey = new Uint8Array(cfg.authorityPubkey);
    this.agent = new Agent({
      keepAlive: cfg.keepAlive ?? true,
      cert: cfg.clientCertPem,
      key: cfg.clientKeyPem,
      ca: cfg.caPem,
    });
  }

  public async relayRefusal(input: RelayRefusalInput): Promise<VerifiedRefusal> {
    const body: Record<string, unknown> = {
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      reasonCode: input.reasonCode,
      proofRef: input.proofRef,
    };
    if (input.reasonPlaintextHex !== undefined) body.reasonPlaintextHex = input.reasonPlaintextHex;
    if (input.timestamp !== undefined) body.timestamp = input.timestamp.toString();

    const responseRaw = await this.postJson("/refuse", body);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(responseRaw) as Record<string, unknown>;
    } catch {
      throw new RefusalRelayError(
        "ERR_RELAY_RESPONSE_PARSE",
        `daemon response is not JSON: ${responseRaw.slice(0, 200)}`,
      );
    }

    const claim = parsed.refusalClaim as
      | { canonicalBytes?: unknown; ed25519Sig?: unknown; domainLabel?: unknown }
      | undefined;
    if (
      !claim ||
      typeof claim.canonicalBytes !== "string" ||
      typeof claim.ed25519Sig !== "string" ||
      typeof claim.domainLabel !== "string"
    ) {
      throw new RefusalRelayError(
        "ERR_RELAY_RESPONSE_MISSING_CLAIM",
        `daemon response missing/malformed refusalClaim: ${JSON.stringify(parsed).slice(0, 200)}`,
      );
    }

    // VERIFY — the load-bearing step that closes the audit-verifiability loop.
    const canonicalBytes = refusalClaimHexToBytes(claim.canonicalBytes);
    const ed25519Sig = refusalClaimHexToBytes(claim.ed25519Sig);
    const verify = verifyRefusalClaim({
      canonicalBytes,
      ed25519Sig,
      authorityPubkey: this.authorityPubkey,
    });
    if (!verify.ok) {
      throw new RefusalRelayError(
        verify.error,
        `daemon refusal claim failed verification: ${verify.detail ?? "(no detail)"}`,
      );
    }

    return {
      claim: {
        canonicalBytes: claim.canonicalBytes,
        ed25519Sig: claim.ed25519Sig,
        domainLabel: claim.domainLabel,
      },
      parsed: verify.parsed,
      daemonMode: typeof parsed.mode === "string" ? parsed.mode : "unknown",
      daemonReportedTxHash:
        typeof parsed.txHash === "string"
          ? parsed.txHash
          : "0x0000000000000000000000000000000000000000000000000000000000000000",
      encryptedBlobHash:
        typeof parsed.encryptedBlobHash === "string" ? parsed.encryptedBlobHash : undefined,
    };
  }

  public close(): void {
    this.agent.destroy();
  }

  // ── internal ──

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
        (res: IncomingMessage) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            const buf = Buffer.concat(chunks).toString("utf8");
            if (res.statusCode !== 200) {
              reject(
                new RefusalRelayError(
                  "ERR_RELAY_HTTP_STATUS",
                  `daemon /refuse returned HTTP ${res.statusCode}: ${buf.slice(0, 200)}`,
                  res.statusCode,
                  buf,
                ),
              );
              return;
            }
            resolve(buf);
          });
          res.on("error", (e) =>
            reject(new RefusalRelayError("ERR_RELAY_NETWORK", `response stream error: ${e.message}`)),
          );
        },
      );
      req.setTimeout(this.timeoutMs, () => {
        req.destroy(
          new RefusalRelayError(
            "ERR_RELAY_TIMEOUT",
            `daemon /refuse request timed out after ${this.timeoutMs}ms`,
          ),
        );
      });
      req.on("error", (e) =>
        reject(
          e instanceof RefusalRelayError
            ? e
            : new RefusalRelayError("ERR_RELAY_NETWORK", `request error: ${e.message}`),
        ),
      );
      req.end(payload);
    });
  }
}
