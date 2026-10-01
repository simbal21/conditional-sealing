// G4 refusal-claim verifier — closes the audit-verifiability loop.
//
// The daemon (v3-custody/g4-phase1/server/refusal-claim.ts) emits an
// Ed25519-signed claim with /refuse responses. The CLAIM is off-chain audit-grade
// evidence: "the daemon at this authority pubkey authorized this refusal." This
// verifier is what an auditor (or the orchestrator's defense-in-depth check) uses to
// confirm the claim is valid before trusting / persisting / writing-to-chain.
//
// Verification covers TWO axes:
//   1. Byte layout: the canonical bytes parse correctly (138 bytes, correct domain
//      tag, valid reasonCode 0x01-0x0A, no malformed offsets).
//   2. Signature: Ed25519 over the canonical bytes verifies against the supplied
//      authority pubkey (which the caller obtains from G4AuthorityRegistry.sol read).
//
// NON-GOALS:
//   - This verifier does NOT check whether the refusal makes business sense (e.g., is
//     there actually an Art.17 erasure request for this authorizationId?). That's a
//     higher-layer concern; the claim is "the daemon agreed," not "the refusal was
//     justified." The orchestrator's chain-write happens regardless of this verifier —
//     this verifier provides POST-HOC audit assurance.
//   - This verifier does NOT fetch the authority pubkey itself. Caller passes it.
//     This keeps the verifier pure + free of chain dependencies + testable in isolation.

import { ed25519 } from "@noble/curves/ed25519";
import { createHash } from "node:crypto";

const DOMAIN_LABEL = "CEALIS_V3_G4_REFUSAL_CLAIM_V1";
const CANONICAL_BYTES_LEN = 138;
const MIN_REASON = 0x01;
const MAX_REASON = 0x0a;

let cachedDomainTag: Uint8Array | undefined;
function getDomainTag(): Uint8Array {
  if (cachedDomainTag === undefined) {
    cachedDomainTag = createHash("sha256").update(DOMAIN_LABEL, "utf8").digest();
  }
  return cachedDomainTag;
}

export const RefusalClaimVerifyError = {
  ERR_CLAIM_CANONICAL_LEN: "ERR_CLAIM_CANONICAL_LEN",
  ERR_CLAIM_DOMAIN_TAG_MISMATCH: "ERR_CLAIM_DOMAIN_TAG_MISMATCH",
  ERR_CLAIM_REASON_OUT_OF_RANGE: "ERR_CLAIM_REASON_OUT_OF_RANGE",
  ERR_CLAIM_ENC_PRESENT_INVALID: "ERR_CLAIM_ENC_PRESENT_INVALID",
  ERR_CLAIM_SIG_LEN: "ERR_CLAIM_SIG_LEN",
  ERR_CLAIM_AUTHORITY_PUBKEY_LEN: "ERR_CLAIM_AUTHORITY_PUBKEY_LEN",
  ERR_CLAIM_SIG_VERIFY: "ERR_CLAIM_SIG_VERIFY",
} as const;

export type RefusalClaimVerifyErrorCode = keyof typeof RefusalClaimVerifyError;

export type RefusalClaimVerifyResult =
  | { readonly ok: true; readonly parsed: ParsedRefusalClaim }
  | { readonly ok: false; readonly error: RefusalClaimVerifyErrorCode; readonly detail?: string };

export interface ParsedRefusalClaim {
  readonly domainTag: Uint8Array;
  readonly authorizationId: Uint8Array;
  readonly hCommit: Uint8Array;
  readonly reasonCode: number;
  readonly encryptedReasonPresent: boolean;
  readonly encryptedBlobHash?: Uint8Array;
  readonly timestamp: bigint;
}

export interface RefusalClaimVerifyInput {
  /** 138-byte canonical input as bytes (callers convert from hex if needed). */
  readonly canonicalBytes: Uint8Array;
  /** 64-byte Ed25519 signature as bytes. */
  readonly ed25519Sig: Uint8Array;
  /** Ed25519 authority pubkey as 32 raw bytes (NOT PEM). Caller obtains from
   *  G4AuthorityRegistry.sol read OR from the daemon's known authority entry. */
  readonly authorityPubkey: Uint8Array;
}

/**
 * Verify a refusal claim. Returns `{ok: true, parsed}` on success or
 * `{ok: false, error, detail?}` with a typed error code on any failure. Never throws.
 *
 * Verification order matters: structural checks first (cheap), then signature (~ms).
 * A caller that has untrusted input (e.g., the daemon's response from network) should
 * call this BEFORE persisting the claim or making chain writes based on it.
 */
export function verifyRefusalClaim(input: RefusalClaimVerifyInput): RefusalClaimVerifyResult {
  if (input.canonicalBytes.length !== CANONICAL_BYTES_LEN) {
    return {
      ok: false,
      error: "ERR_CLAIM_CANONICAL_LEN",
      detail: `canonical bytes length ${input.canonicalBytes.length} != ${CANONICAL_BYTES_LEN}`,
    };
  }
  if (input.ed25519Sig.length !== 64) {
    return {
      ok: false,
      error: "ERR_CLAIM_SIG_LEN",
      detail: `Ed25519 signature length ${input.ed25519Sig.length} != 64`,
    };
  }
  if (input.authorityPubkey.length !== 32) {
    return {
      ok: false,
      error: "ERR_CLAIM_AUTHORITY_PUBKEY_LEN",
      detail: `authority pubkey length ${input.authorityPubkey.length} != 32`,
    };
  }

  // Parse the canonical bytes — checks domain tag + reason range + enc-present byte.
  const expectedDomainTag = getDomainTag();
  const domainTagSlice = input.canonicalBytes.subarray(0, 32);
  if (!bytesEqual(domainTagSlice, expectedDomainTag)) {
    return {
      ok: false,
      error: "ERR_CLAIM_DOMAIN_TAG_MISMATCH",
      detail: `domain tag does not match SHA-256("${DOMAIN_LABEL}")`,
    };
  }
  const authorizationId = input.canonicalBytes.subarray(32, 64);
  const hCommit = input.canonicalBytes.subarray(64, 96);
  const reasonCode = input.canonicalBytes[96];
  if (reasonCode === undefined || reasonCode < MIN_REASON || reasonCode > MAX_REASON) {
    return {
      ok: false,
      error: "ERR_CLAIM_REASON_OUT_OF_RANGE",
      detail: `reasonCode 0x${reasonCode?.toString(16) ?? "??"} outside [0x01..0x0A]`,
    };
  }
  const encPresentByte = input.canonicalBytes[97];
  if (encPresentByte !== 0 && encPresentByte !== 1) {
    return {
      ok: false,
      error: "ERR_CLAIM_ENC_PRESENT_INVALID",
      detail: `encryptedReasonPresent byte must be 0x00 or 0x01, got 0x${encPresentByte?.toString(16)}`,
    };
  }
  const encryptedReasonPresent = encPresentByte === 1;
  const blobHashSlice = input.canonicalBytes.subarray(98, 130);
  const encryptedBlobHash = encryptedReasonPresent
    ? new Uint8Array(blobHashSlice)
    : undefined;
  const timestamp = readUint64BE(input.canonicalBytes.subarray(130, 138));

  // Ed25519 signature verify (the expensive step — last).
  let sigOk = false;
  try {
    sigOk = ed25519.verify(input.ed25519Sig, input.canonicalBytes, input.authorityPubkey);
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
      domainTag: new Uint8Array(expectedDomainTag),
      authorizationId: new Uint8Array(authorizationId),
      hCommit: new Uint8Array(hCommit),
      reasonCode,
      encryptedReasonPresent,
      encryptedBlobHash,
      timestamp,
    },
  };
}

// ── helpers (private) ──

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function readUint64BE(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) throw new Error(`readUint64BE: expected 8 bytes, got ${bytes.length}`);
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

/** Convenience: hex string (with or without 0x) → bytes. */
export function refusalClaimHexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) throw new Error("hex string must be even length");
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
