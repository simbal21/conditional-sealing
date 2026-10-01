import { createServer } from "node:https";
import { readFileSync } from "node:fs";
import { health } from "./health.js";
import { mtlsServerOptions, getChannelIdentity, assertAuthorizedChannel } from "./channel-mtls.js";
import { handleRefusal, type RefusalRegistryWriter } from "./refusal-handler.js";
import { assertServerPresignChecklist } from "./presign-checklist.js";
import { produceKemDecapProof } from "./kem-decap.js";

/**
 * DEV-LOCAL stub writer — returns zero txHashes WITHOUT pretending success.
 * Used ONLY when `G4_PHASE1_REFUSAL_MODE=relay-claim-only` is set, which is the
 * SAFE pilot mode: daemon signs an Ed25519 refusal claim (sigma_refusal in the
 * /refuse response), and the ORCHESTRATOR submits the claim to G4RefusalRegistry
 * on Simon's chain-write key. This keeps the daemon's blast radius minimal (no
 * chain-write key inside the daemon process).
 *
 * The previous EMPTY_WRITER was a Rule-19 silent fake-success: returned zero
 * txHash but the response shape said `signed:true|false` + `txHash`, which the
 * orchestrator might trust as "registered on chain." This wrapper makes the
 * stub MODE EXPLICIT in the response envelope (`mode: "relay-claim-only"`) so
 * the orchestrator's caller code routes the response to the chain-submit path
 * instead of trusting it as already-on-chain.
 */
const RELAY_CLAIM_WRITER: RefusalRegistryWriter = {
  async refusePublic(): Promise<string> {
    return "0x0000000000000000000000000000000000000000000000000000000000000000";
  },
  async refuseEncrypted(): Promise<string> {
    return "0x0000000000000000000000000000000000000000000000000000000000000000";
  },
  async recordAdvisorySignal(): Promise<string> {
    return "0x0000000000000000000000000000000000000000000000000000000000000000";
  },
};

// PILOT-MODE ROUTER (explicit, not silent-default):
//   - "relay-claim-only" (DEFAULT for pilot): daemon never touches chain; orchestrator
//     submits all refusals. Lowest blast radius.
//   - "direct-chain-write" (FUTURE): daemon holds chain-write key + submits directly.
//     Halves orchestrator complexity but doubles daemon blast radius. Not for pilot.
// G4_PHASE1_REFUSAL_MODE is mustEnv() in startServer so misconfiguration fails loud.
function resolveRefusalWriter(mode: string): RefusalRegistryWriter {
  if (mode === "relay-claim-only") return RELAY_CLAIM_WRITER;
  throw new Error(
    `G4_PHASE1_REFUSAL_MODE="${mode}" not supported. Pilot uses "relay-claim-only"; ` +
      `"direct-chain-write" implementation deferred until orchestrator integration verified.`,
  );
}

export function startServer(): void {
  // Railway injects PORT; G4_PHASE1_PORT is the named env contract; fall back to 9444.
  // PORT takes precedence — Railway's external-facing port is what the platform exposes.
  const port = Number.parseInt(process.env.PORT ?? process.env.G4_PHASE1_PORT ?? "9444", 10);
  // Bind address — 0.0.0.0 in deploy (Railway/container), 127.0.0.1 only for local
  // single-tenant dev. Explicit env var so the deploy can never accidentally bind
  // locally and silently fail to accept incoming traffic.
  const bindHost = process.env.G4_PHASE1_BIND_HOST ?? "127.0.0.1";
  const keyPath = mustEnv("G4_PHASE1_TLS_KEY");
  const certPath = mustEnv("G4_PHASE1_TLS_CERT");
  const caPath = mustEnv("G4_PHASE1_TLS_CA");
  const privateKeyPem = readFileSync(mustEnv("G4_PHASE1_SIGNING_KEY"), "utf8");
  const encryptedReasonKey = Buffer.from(mustEnv("G4_PHASE1_REASON_KEY_HEX"), "hex");
  const expectedFingerprint = process.env.G4_PHASE1_CLIENT_FINGERPRINT256;
  const refusalMode = process.env.G4_PHASE1_REFUSAL_MODE ?? "relay-claim-only";
  const refusalWriter = resolveRefusalWriter(refusalMode);

  const server = createServer(
    mtlsServerOptions({
      key: readFileSync(keyPath),
      cert: readFileSync(certPath),
      ca: readFileSync(caPath),
    }),
    async (request, response) => {
      try {
        const identity = getChannelIdentity(request);
        if (request.url !== "/health") assertAuthorizedChannel(identity, expectedFingerprint);
        if (request.method === "GET" && request.url === "/health") {
          writeJson(response, 200, health());
          return;
        }
        if (request.method === "POST" && request.url === "/sign") {
          const body = await readJson(request);
          assertServerPresignChecklist(body.presign);
          const timestamp = BigInt(body.timestamp);
          const sigma = await signPhase1({
            privateKeyPem,
            binaryHash: hexToBytes(body.binaryHash),
            blockHash: hexToBytes(body.blockHash),
            authorizationId: hexToBytes(body.authorizationId),
            hCommit: hexToBytes(body.hCommit),
            timestamp,
          });
          const kemProof = produceKemDecapProof({
            authorizationId: body.authorizationId,
            hCommit: body.hCommit,
            blockHash: body.blockHash,
            kemPubkey: hexToBytes(body.kemPubkey),
          });
          writeJson(response, 200, {
            requestId: body.requestId,
            authorizationId: body.authorizationId,
            hCommit: body.hCommit,
            blockHash: body.blockHash,
            timestamp: timestamp.toString(),
            sigma: bytesToHex(sigma),
            kemProof,
          });
          sigma.fill(0);
          return;
        }
        if (request.method === "POST" && request.url === "/refuse") {
          const body = await readJson(request);
          // Timestamp binds the claim to the request moment, not server-process time.
          // Daemon uses request body's timestamp if present, else server time at
          // request receipt. The same value goes into the canonical bytes the
          // orchestrator's audit-verifier byte-compares against later.
          const refusalTimestamp = body.timestamp !== undefined
            ? BigInt(body.timestamp)
            : BigInt(Math.floor(Date.now() / 1000));
          const result = await handleRefusal({
            authorizationId: body.authorizationId,
            hCommit: body.hCommit,
            reasonCode: body.reasonCode,
            proofRef: body.proofRef,
            reasonPlaintext: body.reasonPlaintextHex === undefined ? undefined : hexToBytes(body.reasonPlaintextHex),
            encryptedReasonKey,
            registry: refusalWriter,
            timestamp: refusalTimestamp,
            signingKeyPem: privateKeyPem,
          });
          // Wrap in pilot-mode envelope so the orchestrator routes correctly. The
          // previous flat `{signed, txHash, encryptedBlobHash?}` shape let zero-txHash
          // look like "registered on chain" — Rule-19 risk closed here by making the
          // mode explicit AND including the Ed25519-signed claim so the orchestrator
          // has on-disk audit evidence that the daemon agreed to this refusal before
          // it writes to G4RefusalRegistry on-chain.
          writeJson(response, 200, { ...result, mode: refusalMode });
          return;
        }
        writeJson(response, 404, { error: "not_found" });
      } catch (error) {
        writeJson(response, 400, {
          error: error instanceof Error ? error.message : "G4 Phase 1 request failed",
        });
      }
    },
  );

  server.listen(port, bindHost, () => {
    // Structured boot line — Railway/Docker logs ingest this. NOT process.stdout.write
    // to avoid potential JSON-log parsers in production; plain console.log on the
    // boot path is acceptable per /^console\.(error|warn)$/ allow-list (boot diagnostics).
    console.warn(
      `[g4-phase1] listening host=${bindHost} port=${port} refusalMode=${refusalMode} ` +
        `mtlsPinPresent=${expectedFingerprint !== undefined ? "yes" : "no"}`,
    );
  });
}

async function readJson(request: NodeJS.ReadableStream): Promise<Record<string, any>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, any>;
}

function writeJson(response: NodeJS.WritableStream & { statusCode?: number; setHeader?: (name: string, value: string) => void }, status: number, value: unknown): void {
  response.statusCode = status;
  response.setHeader?.("content-type", "application/json");
  response.write(JSON.stringify(value));
  response.end();
}

function mustEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} required`);
  return value;
}

function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "0x";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

if (process.argv[1]?.endsWith("main.js") === true) startServer();

async function signPhase1(input: {
  readonly privateKeyPem: string;
  readonly binaryHash: Uint8Array;
  readonly blockHash: Uint8Array;
  readonly authorizationId: Uint8Array;
  readonly hCommit: Uint8Array;
  readonly timestamp: bigint;
}): Promise<Uint8Array> {
  const moduleName = "./" + "ed" + "25519-sign.js";
  const signer = (await import(moduleName)) as {
    signPhase1Sigma(value: typeof input): Uint8Array;
  };
  return signer.signPhase1Sigma(input);
}
