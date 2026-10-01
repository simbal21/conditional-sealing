#!/usr/bin/env node
// audit-CLI: standalone refusal-claim verifier.
//
// Auditors / partners / regulators use this to independently verify a G4 refusal claim
// against the daemon's registered authority pubkey. No orchestrator dependency, no
// chain RPC, no filesystem state — pure function over the input.
//
// USAGE:
//   node verify-refusal-claim.mjs --pubkey-hex 0x<32-byte-hex> --claim-file <path.json>
//   node verify-refusal-claim.mjs --pubkey-hex 0x... < claim.json
//   node verify-refusal-claim.mjs --pubkey-pem signing.pub --claim-file claim.json
//   node verify-refusal-claim.mjs --help
//
// INPUT FORMAT (claim.json) — exactly the shape the daemon emits in /refuse response:
//   {
//     "refusalClaim": {
//       "canonicalBytes": "0x<138-byte-hex>",
//       "ed25519Sig":     "0x<64-byte-hex>",
//       "domainLabel":    "CEALIS_V3_G4_REFUSAL_CLAIM_V1"
//     }
//   }
// OR (just the inner claim):
//   { "canonicalBytes": "...", "ed25519Sig": "...", "domainLabel": "..." }
//
// EXIT CODES:
//   0 — verified OK; parsed fields printed to stdout as JSON
//   1 — verification failed (any error); typed error code + detail printed to stderr
//   2 — usage error (bad arguments)
//
// WHAT THIS PROVES (audit semantic):
//   "The daemon at the given authority pubkey signed THESE EXACT canonical bytes."
//   This is the cryptographic primitive that closes fraud-by-refusal — an orchestrator
//   that submits a refusal to G4RefusalRegistry on-chain without a matching
//   daemon-signed claim cannot, post-hoc, fabricate one (Ed25519 sigs are not
//   forgeable without the private key).
//
// AUDIT WORKFLOW:
//   1. Auditor fetches the orchestrator's stored refusal claims (off-chain log).
//   2. For each claim, fetches the corresponding daemon's authority pubkey from
//      G4AuthorityRegistry.sol (Base Sepolia / mainnet read) at the claim's
//      authorization block.
//   3. Runs `node verify-refusal-claim.mjs --pubkey-hex <pubkey> --claim-file <claim.json>`
//      for each entry.
//   4. Cross-references against the on-chain G4RefusalRegistry events for the same
//      authorizationId. A refusal on-chain without a matching verified claim =
//      orchestrator wrote unilaterally (audit-failure event).
//
// HERMETIC: only Node stdlib + @noble/curves/ed25519. No filesystem writes. No network.
// Safe to run on air-gapped audit workstations.

import { createHash, createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { argv, exit, stdin, stdout, stderr } from "node:process";
import { ed25519 } from "@noble/curves/ed25519";

const DOMAIN_LABEL = "CEALIS_V3_G4_REFUSAL_CLAIM_V1";
const CANONICAL_BYTES_LEN = 138;
const MIN_REASON = 0x01;
const MAX_REASON = 0x0a;
const DOMAIN_TAG = createHash("sha256").update(DOMAIN_LABEL, "utf8").digest();

const REASON_NAMES = {
  0x01: "LEGAL_COMPEL",
  0x02: "ART_17_ERASURE",
  0x03: "ART_18_RESTRICTION",
  0x04: "INTEGRITY_FAIL",
  0x05: "CHAIN_MISMATCH",
  0x06: "PLUGIN_DEPRECATED",
  0x07: "AUTHORITY_DEPRECATED",
  0x08: "DSL_DEPRECATED",
  0x09: "ORACLE_DEPRECATED",
  0x0a: "OPT_OUT_ACTIVE",
};

// ─── argv parsing ───────────────────────────────────────────────────────────

const args = parseArgs(argv.slice(2));
if (args.help) {
  printHelp();
  exit(0);
}
if (!args.pubkey) {
  errExit(2, "missing --pubkey-hex or --pubkey-pem; see --help");
}

// ─── load authority pubkey ──────────────────────────────────────────────────

let authorityPubkey;
try {
  authorityPubkey = await loadAuthorityPubkey(args.pubkey);
} catch (e) {
  errExit(2, `cannot load authority pubkey: ${e.message}`);
}

// ─── load claim ─────────────────────────────────────────────────────────────

let claimJson;
try {
  const raw = args.claimFile
    ? await readFile(args.claimFile, "utf8")
    : await readStdin();
  claimJson = JSON.parse(raw);
} catch (e) {
  errExit(2, `cannot read/parse claim input: ${e.message}`);
}

// Accept both wrapped { refusalClaim: {...} } and flat { canonicalBytes, ed25519Sig, domainLabel }.
const claim = claimJson.refusalClaim ?? claimJson;
if (typeof claim.canonicalBytes !== "string" || typeof claim.ed25519Sig !== "string") {
  errExit(
    2,
    "claim input missing required string fields canonicalBytes + ed25519Sig",
  );
}

// ─── verify ─────────────────────────────────────────────────────────────────

const result = verifyRefusalClaim({
  canonicalBytes: hexToBytes(claim.canonicalBytes),
  ed25519Sig: hexToBytes(claim.ed25519Sig),
  authorityPubkey,
});

if (!result.ok) {
  stderr.write(
    JSON.stringify(
      { ok: false, error: result.error, detail: result.detail },
      null,
      2,
    ) + "\n",
  );
  exit(1);
}

stdout.write(
  JSON.stringify(
    {
      ok: true,
      verified: "the daemon at this authority pubkey signed these exact canonical bytes",
      parsed: {
        authorizationId: bytesToHex(result.parsed.authorizationId),
        hCommit: bytesToHex(result.parsed.hCommit),
        reasonCode: result.parsed.reasonCode,
        reasonName: REASON_NAMES[result.parsed.reasonCode] ?? `unknown(0x${result.parsed.reasonCode.toString(16)})`,
        encryptedReasonPresent: result.parsed.encryptedReasonPresent,
        encryptedBlobHash: result.parsed.encryptedBlobHash
          ? bytesToHex(result.parsed.encryptedBlobHash)
          : null,
        timestamp: result.parsed.timestamp.toString(),
        timestamp_iso: new Date(Number(result.parsed.timestamp) * 1000).toISOString(),
      },
      domainLabel: DOMAIN_LABEL,
    },
    null,
    2,
  ) + "\n",
);
exit(0);

// ─── pure verifier (mirrors verifyRefusalClaim in @cealis/v3-custody) ───────

function verifyRefusalClaim({ canonicalBytes, ed25519Sig, authorityPubkey }) {
  if (canonicalBytes.length !== CANONICAL_BYTES_LEN) {
    return {
      ok: false,
      error: "ERR_CLAIM_CANONICAL_LEN",
      detail: `canonical bytes length ${canonicalBytes.length} != ${CANONICAL_BYTES_LEN}`,
    };
  }
  if (ed25519Sig.length !== 64) {
    return {
      ok: false,
      error: "ERR_CLAIM_SIG_LEN",
      detail: `Ed25519 signature length ${ed25519Sig.length} != 64`,
    };
  }
  if (authorityPubkey.length !== 32) {
    return {
      ok: false,
      error: "ERR_CLAIM_AUTHORITY_PUBKEY_LEN",
      detail: `authority pubkey length ${authorityPubkey.length} != 32`,
    };
  }
  const domainTagSlice = canonicalBytes.subarray(0, 32);
  if (!bytesEqual(domainTagSlice, DOMAIN_TAG)) {
    return {
      ok: false,
      error: "ERR_CLAIM_DOMAIN_TAG_MISMATCH",
      detail: `domain tag does not match SHA-256("${DOMAIN_LABEL}")`,
    };
  }
  const authorizationId = canonicalBytes.subarray(32, 64);
  const hCommit = canonicalBytes.subarray(64, 96);
  const reasonCode = canonicalBytes[96];
  if (reasonCode === undefined || reasonCode < MIN_REASON || reasonCode > MAX_REASON) {
    return {
      ok: false,
      error: "ERR_CLAIM_REASON_OUT_OF_RANGE",
      detail: `reasonCode 0x${reasonCode?.toString(16) ?? "??"} outside [0x01..0x0A]`,
    };
  }
  const encPresentByte = canonicalBytes[97];
  if (encPresentByte !== 0 && encPresentByte !== 1) {
    return {
      ok: false,
      error: "ERR_CLAIM_ENC_PRESENT_INVALID",
      detail: `encryptedReasonPresent byte must be 0x00 or 0x01, got 0x${encPresentByte?.toString(16)}`,
    };
  }
  const encryptedReasonPresent = encPresentByte === 1;
  const blobHashSlice = canonicalBytes.subarray(98, 130);
  const encryptedBlobHash = encryptedReasonPresent ? new Uint8Array(blobHashSlice) : undefined;
  const timestamp = readUint64BE(canonicalBytes.subarray(130, 138));

  let sigOk = false;
  try {
    sigOk = ed25519.verify(ed25519Sig, canonicalBytes, authorityPubkey);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    return {
      ok: false,
      error: "ERR_CLAIM_SIG_VERIFY",
      detail: "Ed25519 signature does not verify against authority pubkey",
    };
  }
  return {
    ok: true,
    parsed: {
      authorizationId: new Uint8Array(authorizationId),
      hCommit: new Uint8Array(hCommit),
      reasonCode,
      encryptedReasonPresent,
      encryptedBlobHash,
      timestamp,
    },
  };
}

// ─── helpers ────────────────────────────────────────────────────────────────

function parseArgs(av) {
  const out = { help: false, pubkey: null, pubkeyKind: null, claimFile: null };
  for (let i = 0; i < av.length; i++) {
    const a = av[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--pubkey-hex") { out.pubkey = av[++i]; out.pubkeyKind = "hex"; }
    else if (a === "--pubkey-pem") { out.pubkey = av[++i]; out.pubkeyKind = "pem"; }
    else if (a === "--claim-file") out.claimFile = av[++i];
    else errExit(2, `unknown argument: ${a} (see --help)`);
  }
  return out;
}

function printHelp() {
  stdout.write(`audit-CLI: standalone verifier for Cealis G4 refusal claims.

USAGE:
  node verify-refusal-claim.mjs --pubkey-hex 0x<64-hex> --claim-file <path.json>
  node verify-refusal-claim.mjs --pubkey-pem <signing.pub> --claim-file <path.json>
  node verify-refusal-claim.mjs --pubkey-hex 0x... < claim.json
  node verify-refusal-claim.mjs --help

ARGUMENTS:
  --pubkey-hex HEX     Raw 32-byte Ed25519 pubkey as 0x-prefixed hex.
  --pubkey-pem PATH    Path to a PEM-encoded Ed25519 public key (SPKI format,
                       as emitted by \`openssl genpkey -algorithm ed25519\`).
  --claim-file PATH    Path to JSON file with the refusal claim. If omitted,
                       reads JSON from stdin.

INPUT FORMAT:
  { "refusalClaim": { "canonicalBytes": "0x...", "ed25519Sig": "0x...",
                      "domainLabel": "CEALIS_V3_G4_REFUSAL_CLAIM_V1" } }
  OR flat (no wrapping object):
  { "canonicalBytes": "0x...", "ed25519Sig": "0x...", "domainLabel": "..." }

EXIT:
  0 = verified (stdout JSON with parsed fields)
  1 = verification failed (stderr JSON with error code)
  2 = usage error
`);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function loadAuthorityPubkey(pubkeyArg) {
  if (args.pubkeyKind === "hex") {
    const bytes = hexToBytes(pubkeyArg);
    if (bytes.length !== 32) throw new Error(`hex pubkey must be 32 bytes (got ${bytes.length})`);
    return bytes;
  }
  // PEM
  const pem = await readFile(pubkeyArg, "utf8");
  const keyObj = createPublicKey(pem);
  const der = keyObj.export({ type: "spki", format: "der" });
  // Raw 32-byte Ed25519 pubkey is the last 32 bytes of the DER SPKI encoding.
  return new Uint8Array(der.subarray(der.length - 32));
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function readUint64BE(bytes) {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

function hexToBytes(hex) {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) throw new Error("hex string must be even length");
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let hex = "0x";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function errExit(code, msg) {
  stderr.write(`error: ${msg}\n`);
  exit(code);
}
