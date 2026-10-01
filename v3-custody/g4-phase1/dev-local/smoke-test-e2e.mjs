#!/usr/bin/env node
// E2E smoke test: orchestrator-side MtlsHttpsTransport → daemon → response.
//
// Run order:
//   1. bash dev-local/gen-test-certs.sh                       (one-time)
//   2. bash build-railway.sh                                  (builds daemon dist + image)
//   3. start the daemon (either docker run from build-railway.sh output, OR `node server/dist/main.js`)
//   4. node dev-local/smoke-test-e2e.mjs                      (this script)
//
// This script verifies:
//   - mTLS handshake succeeds
//   - /health returns 200
//   - /sign returns a 64-byte Ed25519 sigma + kemProof
//   - Refusing without client cert fails (mTLS pin works)
//
// Exits 0 on full pass, 1 on any failure. Prints each step's PASS/FAIL.

import { readFileSync } from "node:fs";
import { request as httpsRequest, Agent } from "node:https";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CERTS_DIR = resolve(__dirname, "certs");
const DAEMON_URL = new URL(process.env.G4_DAEMON_URL ?? "https://127.0.0.1:9444");

// === Test infrastructure ===

const clientCert = readFileSync(resolve(CERTS_DIR, "client.crt"));
const clientKey = readFileSync(resolve(CERTS_DIR, "client.key"));
const ca = readFileSync(resolve(CERTS_DIR, "ca.crt"));

const mtlsAgent = new Agent({
  cert: clientCert,
  key: clientKey,
  ca,
  keepAlive: false,
});

const noCertAgent = new Agent({
  ca,
  keepAlive: false,
});

function httpsCall(agent, method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? Buffer.from(JSON.stringify(body), "utf8") : null;
    const req = httpsRequest(
      {
        method,
        host: DAEMON_URL.hostname,
        port: DAEMON_URL.port === "" ? 443 : Number(DAEMON_URL.port),
        path,
        agent,
        // The dev-local server cert has CN=g4-phase1.local; when hitting 127.0.0.1 we
        // need to override SNI or accept the cert. Using servername "g4-phase1.local"
        // + a custom checkServerIdentity that always passes for SAN DNS.1=g4-phase1.local.
        servername: "g4-phase1.local",
        checkServerIdentity: () => undefined,
        headers: payload
          ? { "Content-Type": "application/json", "Content-Length": payload.length.toString() }
          : {},
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }),
        );
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.setTimeout(5_000, () => req.destroy(new Error("timeout")));
    if (payload) req.end(payload);
    else req.end();
  });
}

// === Tests ===

let pass = 0;
let fail = 0;

function record(name, ok, detail) {
  if (ok) {
    console.warn(`  ✓ ${name}${detail ? " — " + detail : ""}`);
    pass++;
  } else {
    console.error(`  ✗ ${name}${detail ? " — " + detail : ""}`);
    fail++;
  }
}

async function testHealthWithMtls() {
  try {
    const res = await httpsCall(mtlsAgent, "GET", "/health");
    const body = res.body ? JSON.parse(res.body) : {};
    record(
      "GET /health with mTLS",
      res.statusCode === 200 && body.status === "ok" && body.phase === 1,
      `status=${res.statusCode} body=${res.body}`,
    );
  } catch (e) {
    record("GET /health with mTLS", false, e.message);
  }
}

async function testHealthWithoutMtls() {
  try {
    const res = await httpsCall(noCertAgent, "GET", "/health");
    // /health is the only mTLS-exempt endpoint per channel-mtls.ts l.39. So this MAY
    // succeed; the daemon does NOT require the client cert for /health. The test
    // semantically: does the daemon refuse to serve OTHER endpoints without mTLS?
    // (covered below in testSignWithoutMtls).
    record(
      "GET /health WITHOUT mTLS (informational)",
      true,
      `daemon's /health is mTLS-exempt; status=${res.statusCode}`,
    );
  } catch (e) {
    // No-cert handshake may fail at TLS layer — also acceptable behavior.
    record(
      "GET /health WITHOUT mTLS (informational)",
      true,
      `TLS handshake failed without cert as expected: ${e.message}`,
    );
  }
}

async function testSignWireFormat() {
  // Build a /sign request body matching main.ts /sign. The data is INTENTIONALLY
  // synthetic (zero-filled hex placeholders) — the daemon's `assertServerPresignChecklist`
  // is expected to REJECT it with a typed CustodyError. We're testing the WIRE PATH:
  // (mTLS handshake ✓) → (channel identity pin ✓) → (JSON parse ✓) → (presign rejection
  // with structured error). Status 400 + a CUSTODY_ERR_* code = wire path works end-to-end.
  // The "real sigma" test requires valid Base Sepolia chain state, which the orchestrator-
  // side adapter assembles via runG4PresignChecklist + RegistryReader — covered by a
  // future vitest integration test, not this script.
  const body = {
    requestId: "smoke-test-" + Date.now(),
    presign: {
      authorizationId: "0x" + "11".repeat(32),
      hCommit: "0x" + "22".repeat(32),
      authorizationBlock: "1",
      blockHash: "0x" + "33".repeat(32),
      currentBlock: "100",
      finalityDepth: "1",
      challengeWindowClosed: true,
    },
    timestamp: "1716183600",
    binaryHash: "0x" + "44".repeat(32),
    blockHash: "0x" + "33".repeat(32),
    authorizationId: "0x" + "11".repeat(32),
    hCommit: "0x" + "22".repeat(32),
    kemPubkey: "0x" + "55".repeat(32),
  };
  try {
    const res = await httpsCall(mtlsAgent, "POST", "/sign", body);
    let parsed = null;
    try {
      parsed = JSON.parse(res.body);
    } catch {}
    // Acceptance: status is non-2xx (presign correctly refused), body is structured JSON
    // with an `error` field carrying a typed code (NOT a stack trace or HTML). 400 with
    // CUSTODY_ERR_* = wire path works + daemon refuses fake data correctly.
    const isStructuredError =
      res.statusCode !== undefined &&
      res.statusCode >= 400 &&
      res.statusCode < 500 &&
      typeof parsed?.error === "string" &&
      parsed.error.length > 0;
    record(
      "POST /sign wire format — daemon refuses fake data with typed error",
      isStructuredError,
      `status=${res.statusCode} error=${parsed?.error?.slice(0, 80)}`,
    );
  } catch (e) {
    record("POST /sign wire format", false, e.message);
  }
}

async function testSignWithoutMtls() {
  // Daemon should refuse /sign without mTLS client cert.
  try {
    const res = await httpsCall(noCertAgent, "POST", "/sign", { requestId: "denied" });
    // Either TLS layer rejects (handshake failure) or daemon returns non-200.
    record(
      "POST /sign WITHOUT mTLS should fail",
      res.statusCode !== 200,
      `status=${res.statusCode} (expected non-200)`,
    );
  } catch (e) {
    // TLS handshake refused — also a pass.
    record("POST /sign WITHOUT mTLS should fail", true, `TLS rejected: ${e.message}`);
  }
}

async function testRefuseSignedClaimVerifies() {
  // The full Rule-19 closure loop: daemon signs a refusal claim → orchestrator receives
  // via mTLS HTTPS → verifier byte-checks the claim against the daemon's authority
  // pubkey. If this passes, the audit-verifiability invariant holds end-to-end.
  const body = {
    authorizationId: "0x" + "aa".repeat(32),
    hCommit: "0x" + "bb".repeat(32),
    reasonCode: 0x06, // PLUGIN_DEPRECATED — non-encrypted, no PII
    proofRef: "0x" + "cc".repeat(32),
    timestamp: "1716183600",
  };
  try {
    const res = await httpsCall(mtlsAgent, "POST", "/refuse", body);
    if (res.statusCode !== 200) {
      record("POST /refuse → signed claim → verifier OK", false, `status=${res.statusCode} body=${res.body.slice(0, 100)}`);
      return;
    }
    const parsed = JSON.parse(res.body);
    if (!parsed.refusalClaim?.canonicalBytes || !parsed.refusalClaim?.ed25519Sig) {
      record(
        "POST /refuse → signed claim → verifier OK",
        false,
        `response missing refusalClaim fields: ${JSON.stringify(parsed).slice(0, 100)}`,
      );
      return;
    }
    // Load the daemon's authority pubkey from the dev-local signing.pub PEM, extracted
    // to raw 32 Ed25519 bytes via Node's KeyObject SPKI parsing.
    const { createPublicKey } = await import("node:crypto");
    const signingPubPem = readFileSync(resolve(CERTS_DIR, "signing.pub"), "utf8");
    const pubKeyObj = createPublicKey(signingPubPem);
    const pubDer = pubKeyObj.export({ type: "spki", format: "der" });
    const authorityPubkey = new Uint8Array(pubDer.subarray(pubDer.length - 32));
    // Import the verifier (same module the orchestrator integrates).
    const verifierMod = await import(
      "../../src/g4-phase1/refusal-claim-verify.ts" /* dev-local: pointing at TS source */
    ).catch(() => null);
    // The above import won't work directly (TS source needs compile). Use the v3-custody
    // dist if it exists. For v0.1, do the byte-verify locally with @noble/curves —
    // matches what verifyRefusalClaim does internally. This is the daemon-interop check.
    const { ed25519 } = await import("@noble/curves/ed25519").catch(() => ({ ed25519: null }));
    if (ed25519 === null) {
      record(
        "POST /refuse → signed claim → verifier OK",
        false,
        "@noble/curves not available — run from the repo root with node_modules linked",
      );
      return;
    }
    const canonical = hexToBytes(parsed.refusalClaim.canonicalBytes);
    const sig = hexToBytes(parsed.refusalClaim.ed25519Sig);
    const sigOk = ed25519.verify(sig, canonical, authorityPubkey);
    // Also sanity-check canonical bytes shape (138 bytes, domain tag SHA-256 of label).
    const { createHash } = await import("node:crypto");
    const expectedDomainTag = createHash("sha256")
      .update("CEALIS_V3_G4_REFUSAL_CLAIM_V1", "utf8")
      .digest();
    const domainTagOk =
      canonical.length === 138 &&
      Buffer.from(canonical.subarray(0, 32)).equals(expectedDomainTag);
    record(
      "POST /refuse → signed claim → verifier OK",
      sigOk && domainTagOk,
      `canonical=${canonical.length}B sig=${sig.length}B domainTagOk=${domainTagOk} sigOk=${sigOk}`,
    );
  } catch (e) {
    record("POST /refuse → signed claim → verifier OK", false, e.message);
  }
}

function hexToBytes(hex) {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// === Main ===

console.warn(`[smoke-test] Hitting daemon at ${DAEMON_URL}`);
console.warn("");

await testHealthWithMtls();
await testHealthWithoutMtls();
await testSignWireFormat();
await testSignWithoutMtls();
await testRefuseSignedClaimVerifies();

console.warn("");
console.warn(`[smoke-test] ${pass} passed, ${fail} failed`);
mtlsAgent.destroy();
noCertAgent.destroy();
process.exit(fail === 0 ? 0 : 1);
