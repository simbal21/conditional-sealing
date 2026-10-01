// G4 refusal-claim canonical bytes + Ed25519 signature.
//
// Off-chain audit-grade receipt: the daemon Ed25519-signs the canonical bytes of a
// refusal so the orchestrator (which holds OPERATOR_ROLE on G4RefusalRegistry.sol)
// cannot fraudulently post refusals the daemon didn't agree to. Auditors verify the
// claim against the daemon's authority pubkey (registered on G4AuthorityRegistry).
//
// CHAIN INTERACTION: G4RefusalRegistry.sol (contracts/src/g4-refusal/)
// does NOT verify these claims on-chain. It accepts OPERATOR_ROLE writes only. The
// claim is OFF-CHAIN evidence, stored by the orchestrator alongside the txHash for
// post-hoc audit. This matches the existing σ_G4 architecture: the chain trusts the
// gate authority's signature off-chain, the on-chain side is OPERATOR_ROLE-gated.
//
// CANONICAL BYTES LAYOUT (89 bytes, fixed-width, deterministic):
//   off  size  field
//   0    32    domain_tag = keccak256("CEALIS_V3_G4_REFUSAL_CLAIM_V1")
//   32   32    authorizationId
//   64   32    hCommit
//   96   1     reasonCode (uint8)
//   97   1     encryptedReasonPresent (uint8, 0x00 or 0x01)
//   98   32    encryptedReasonBlobHash (zeros if !encryptedReasonPresent)
//   130  8     timestamp (uint64 BE)
//   -> 138 bytes total
//
// DOMAIN-SEPARATION: the domain tag is computed LOCALLY (not registered to the on-chain
// TAG_*_V3 registry) because the claim is off-chain. It is namespaced under the V3
// label scheme to avoid colliding with sigma signing-inputs (which use TAG_G4_ATTESTATION_V3).
// The signing key is the SAME Ed25519 key the daemon uses for sigma (authority key
// registered on G4AuthorityRegistry); domain separation by tag prevents cross-purpose
// signature reuse.

import { createHash, createPrivateKey, sign as nodeSign } from "node:crypto";

const DOMAIN_LABEL = "CEALIS_V3_G4_REFUSAL_CLAIM_V1";
const CANONICAL_BYTES_LEN = 138;

let cachedDomainTag: Uint8Array | undefined;
function getDomainTag(): Uint8Array {
  if (cachedDomainTag === undefined) {
    cachedDomainTag = createHash("sha256").update(DOMAIN_LABEL, "utf8").digest();
  }
  return cachedDomainTag;
}

export interface RefusalClaimInput {
  readonly authorizationId: string; // 0x-hex 32 bytes
  readonly hCommit: string; // 0x-hex 32 bytes
  readonly reasonCode: number; // 0x01..0x0A
  /** SHA-256 hash of encryptedReasonBlob bytes, if Art.17/Art.18 (encrypted reason).
   *  Hex string (with or without 0x). Empty/undefined when not present. */
  readonly encryptedBlobHash?: string;
  /** Unix seconds (matches sigma-sign timestamp). */
  readonly timestamp: bigint;
}

export interface SignedRefusalClaim {
  /** Hex (0x-prefixed) of the 138-byte canonical input the signature covers. */
  readonly canonicalBytes: string;
  /** Hex (0x-prefixed) of the 64-byte Ed25519 signature. */
  readonly ed25519Sig: string;
  /** Domain label that produced the embedded domain_tag (for verifier compat checks). */
  readonly domainLabel: string;
}

/**
 * Build the canonical 138-byte input to sign. Caller passes parsed fields; this module
 * is the SOLE producer of canonical bytes so consumers (audit verifier, future contract
 * extensions) byte-compare against THIS layout.
 */
export function buildRefusalClaimCanonicalBytes(input: RefusalClaimInput): Uint8Array {
  if (input.reasonCode < 0x01 || input.reasonCode > 0x0a) {
    throw new Error(`refusal-claim: invalid reasonCode 0x${input.reasonCode.toString(16)}`);
  }
  const authId = hexToBytes32(input.authorizationId, "authorizationId");
  const hCommit = hexToBytes32(input.hCommit, "hCommit");
  const blobHash = input.encryptedBlobHash
    ? hexToBytes32(input.encryptedBlobHash, "encryptedBlobHash")
    : new Uint8Array(32);
  const encPresent = input.encryptedBlobHash ? 1 : 0;
  const ts = uint64BE(input.timestamp);

  const out = new Uint8Array(CANONICAL_BYTES_LEN);
  let off = 0;
  out.set(getDomainTag(), off);
  off += 32;
  out.set(authId, off);
  off += 32;
  out.set(hCommit, off);
  off += 32;
  out[off++] = input.reasonCode & 0xff;
  out[off++] = encPresent & 0xff;
  out.set(blobHash, off);
  off += 32;
  out.set(ts, off);
  off += 8;
  if (off !== CANONICAL_BYTES_LEN) {
    throw new Error(`refusal-claim: canonical bytes layout drift off=${off} expected=${CANONICAL_BYTES_LEN}`);
  }
  return out;
}

/**
 * Sign the canonical bytes with the daemon's Ed25519 key. Returns the signed claim
 * envelope. PRIVATE KEY HANDLING: caller passes PEM bytes; this module does not hold
 * the key beyond the sync `nodeSign` call. The signature is over the 138-byte input;
 * Ed25519 signatures are deterministic (no nonce-reuse risk).
 */
export function signRefusalClaim(input: RefusalClaimInput, privateKeyPem: string): SignedRefusalClaim {
  const canonical = buildRefusalClaimCanonicalBytes(input);
  const key = createPrivateKey(privateKeyPem);
  const sig = nodeSign(null, canonical, key);
  if (sig.length !== 64) {
    throw new Error(`refusal-claim: Ed25519 signature unexpected length ${sig.length} (expected 64)`);
  }
  return {
    canonicalBytes: bytesToHex(canonical),
    ed25519Sig: bytesToHex(sig),
    domainLabel: DOMAIN_LABEL,
  };
}

// ── helpers ──

function hexToBytes32(hex: string, field: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length !== 64) {
    throw new Error(`refusal-claim: ${field} must be 32-byte hex (got ${stripped.length / 2} bytes)`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function uint64BE(value: bigint): Uint8Array {
  if (value < 0n || value > (1n << 64n) - 1n) {
    throw new Error(`refusal-claim: timestamp out of uint64 range: ${value}`);
  }
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let hex = "0x";
  for (const byte of b) hex += byte.toString(16).padStart(2, "0");
  return hex;
}
