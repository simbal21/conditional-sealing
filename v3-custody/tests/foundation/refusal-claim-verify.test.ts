// Foundation test — G4 refusal-claim verifier (closes audit-verifiability loop).
//
// The daemon (v3-custody/g4-phase1/server/refusal-claim.ts) signs an
// off-chain claim with /refuse responses. This verifier (the partner piece in
// v3-custody/src/g4-phase1/refusal-claim-verify.ts) is what consumers use to confirm
// "the daemon at this authority pubkey authorized this refusal." These tests are the
// adversarial-construction discipline applied to the verifier: every error code MUST
// be reachable via a planted failure, AND happy path MUST succeed end-to-end.

import { describe, it, expect } from "vitest";
import { createHash, createPrivateKey, sign as nodeSign, generateKeyPairSync } from "node:crypto";

import {
  verifyRefusalClaim,
  refusalClaimHexToBytes,
} from "../../src/g4-phase1/refusal-claim-verify.js";

const DOMAIN_LABEL = "CEALIS_V3_G4_REFUSAL_CLAIM_V1";
const DOMAIN_TAG = createHash("sha256").update(DOMAIN_LABEL, "utf8").digest();
const CANONICAL_BYTES_LEN = 138;

/** Build a valid canonical-bytes input (matches the daemon's `buildRefusalClaimCanonicalBytes`). */
function buildCanonical(opts: {
  authorizationId?: Uint8Array;
  hCommit?: Uint8Array;
  reasonCode?: number;
  encryptedReasonPresent?: boolean;
  encryptedBlobHash?: Uint8Array;
  timestamp?: bigint;
}): Uint8Array {
  const authId = opts.authorizationId ?? new Uint8Array(32).fill(0x11);
  const hCommit = opts.hCommit ?? new Uint8Array(32).fill(0x22);
  const reasonCode = opts.reasonCode ?? 0x06;
  const encPresent = opts.encryptedReasonPresent ?? false;
  const blobHash = opts.encryptedBlobHash ?? new Uint8Array(32);
  const timestamp = opts.timestamp ?? 1716183600n;

  const out = new Uint8Array(CANONICAL_BYTES_LEN);
  let off = 0;
  out.set(DOMAIN_TAG, off);
  off += 32;
  out.set(authId, off);
  off += 32;
  out.set(hCommit, off);
  off += 32;
  out[off++] = reasonCode & 0xff;
  out[off++] = encPresent ? 1 : 0;
  out.set(blobHash, off);
  off += 32;
  // uint64 BE timestamp
  let v = timestamp;
  for (let i = 7; i >= 0; i--) {
    out[off + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Generate an Ed25519 keypair + sign canonical bytes. Returns the input verifyRefusalClaim expects. */
function signCanonical(canonical: Uint8Array): {
  authorityPubkey: Uint8Array;
  ed25519Sig: Uint8Array;
  privateKeyPem: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const pubkeyDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  // The raw 32-byte Ed25519 pubkey is the last 32 bytes of the DER SPKI encoding.
  const authorityPubkey = new Uint8Array(pubkeyDer.subarray(pubkeyDer.length - 32));
  const sigBuf = nodeSign(null, canonical, createPrivateKey(privateKeyPem));
  return { authorityPubkey, ed25519Sig: new Uint8Array(sigBuf), privateKeyPem };
}

describe("verifyRefusalClaim — happy path", () => {
  it("accepts a freshly-signed valid claim and parses every field", () => {
    const canonical = buildCanonical({ reasonCode: 0x06, timestamp: 1716183600n });
    const { authorityPubkey, ed25519Sig } = signCanonical(canonical);

    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.parsed.reasonCode).toBe(0x06);
    expect(result.parsed.encryptedReasonPresent).toBe(false);
    expect(result.parsed.encryptedBlobHash).toBeUndefined();
    expect(result.parsed.timestamp).toBe(1716183600n);
    expect(result.parsed.authorizationId.length).toBe(32);
    expect(result.parsed.hCommit.length).toBe(32);
  });

  it("accepts an encrypted-reason claim (Art.17/18) with non-zero blob hash", () => {
    const blobHash = new Uint8Array(32).fill(0xab);
    const canonical = buildCanonical({
      reasonCode: 0x02,
      encryptedReasonPresent: true,
      encryptedBlobHash: blobHash,
    });
    const { authorityPubkey, ed25519Sig } = signCanonical(canonical);

    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.parsed.reasonCode).toBe(0x02);
    expect(result.parsed.encryptedReasonPresent).toBe(true);
    expect(result.parsed.encryptedBlobHash).toBeDefined();
    expect(result.parsed.encryptedBlobHash!.length).toBe(32);
    expect(Array.from(result.parsed.encryptedBlobHash!)).toEqual(Array.from(blobHash));
  });
});

describe("verifyRefusalClaim — structural failures", () => {
  it("rejects wrong canonical-bytes length", () => {
    const tooShort = new Uint8Array(100);
    const { authorityPubkey, ed25519Sig } = signCanonical(buildCanonical({}));
    const result = verifyRefusalClaim({ canonicalBytes: tooShort, ed25519Sig, authorityPubkey });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("ERR_CLAIM_CANONICAL_LEN");
  });

  it("rejects wrong Ed25519 signature length", () => {
    const canonical = buildCanonical({});
    const { authorityPubkey } = signCanonical(canonical);
    const badSig = new Uint8Array(32); // half-length
    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig: badSig, authorityPubkey });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("ERR_CLAIM_SIG_LEN");
  });

  it("rejects wrong authority pubkey length", () => {
    const canonical = buildCanonical({});
    const { ed25519Sig } = signCanonical(canonical);
    const badPubkey = new Uint8Array(16);
    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey: badPubkey });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("ERR_CLAIM_AUTHORITY_PUBKEY_LEN");
  });

  it("rejects wrong domain tag (label collision attack)", () => {
    const canonical = buildCanonical({});
    // Overwrite the domain tag bytes with garbage
    canonical.set(new Uint8Array(32).fill(0xff), 0);
    const { authorityPubkey, ed25519Sig } = signCanonical(canonical); // sign the BAD bytes
    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("ERR_CLAIM_DOMAIN_TAG_MISMATCH");
  });

  it("rejects reason code out of range (0x00, 0x0B+)", () => {
    for (const badReason of [0x00, 0x0b, 0xff]) {
      const canonical = buildCanonical({ reasonCode: badReason });
      const { authorityPubkey, ed25519Sig } = signCanonical(canonical);
      const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey });
      expect(result.ok).toBe(false);
      if (result.ok) continue;
      expect(result.error).toBe("ERR_CLAIM_REASON_OUT_OF_RANGE");
    }
  });

  it("rejects invalid encryptedReasonPresent byte (must be 0x00 or 0x01)", () => {
    const canonical = buildCanonical({});
    canonical[97] = 0x02; // overwrite encPresent byte with invalid value
    const { authorityPubkey, ed25519Sig } = signCanonical(canonical);
    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("ERR_CLAIM_ENC_PRESENT_INVALID");
  });
});

describe("verifyRefusalClaim — signature failures (the attack surface)", () => {
  it("rejects a claim signed by a different authority key", () => {
    const canonical = buildCanonical({});
    const { ed25519Sig } = signCanonical(canonical);
    // Generate a DIFFERENT keypair — caller has the WRONG pubkey for this sig.
    const { authorityPubkey: wrongPubkey } = signCanonical(canonical);
    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey: wrongPubkey });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("ERR_CLAIM_SIG_VERIFY");
  });

  it("rejects a claim where bytes were modified after signing (tamper detection)", () => {
    const canonical = buildCanonical({ reasonCode: 0x06, timestamp: 1716183600n });
    const { authorityPubkey, ed25519Sig } = signCanonical(canonical);
    // Tamper: change reasonCode from 0x06 → 0x02 (the fraud attempt — Art.17 erasure
    // claimed by an attacker who has only a 0x06 plugin-deprecated signed claim).
    canonical[96] = 0x02;
    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("ERR_CLAIM_SIG_VERIFY");
  });

  it("rejects a claim with timestamp tampered (replay-protection-adjacent)", () => {
    const canonical = buildCanonical({ timestamp: 1716183600n });
    const { authorityPubkey, ed25519Sig } = signCanonical(canonical);
    // Tamper the last byte of the timestamp (changes uint64BE last octet).
    canonical[137] = canonical[137]! + 1;
    const result = verifyRefusalClaim({ canonicalBytes: canonical, ed25519Sig, authorityPubkey });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("ERR_CLAIM_SIG_VERIFY");
  });
});

describe("verifyRefusalClaim — hex helper", () => {
  it("refusalClaimHexToBytes accepts both 0x-prefixed and bare hex", () => {
    const withPrefix = refusalClaimHexToBytes("0xdeadbeef");
    const withoutPrefix = refusalClaimHexToBytes("deadbeef");
    expect(Array.from(withPrefix)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(Array.from(withoutPrefix)).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("rejects odd-length hex", () => {
    expect(() => refusalClaimHexToBytes("0xabc")).toThrow();
  });
});

describe("verifyRefusalClaim — daemon interop (the real cross-module check)", () => {
  it("verifies a claim produced by the actual server-side signRefusalClaim path", async () => {
    // Import the daemon-side signer through a dynamic import — the daemon code lives
    // at v3-custody/g4-phase1/server/, not in v3-custody's src/. We use
    // a relative path that walks out of tests/foundation/ into the deploy artifact dir.
    // This is the ONE place we cross the daemon/SDK boundary in tests, to prove the
    // sign + verify pair actually composes.
    const { signRefusalClaim } = await import(
      "../../g4-phase1/server/refusal-claim.js" as string
    );

    // Generate a signing key (PEM)
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const pubkeyDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
    const authorityPubkey = new Uint8Array(pubkeyDer.subarray(pubkeyDer.length - 32));

    const signed = signRefusalClaim(
      {
        authorizationId: "0x" + "11".repeat(32),
        hCommit: "0x" + "22".repeat(32),
        reasonCode: 0x06,
        timestamp: 1716183600n,
      },
      privateKeyPem,
    );

    // Verify the result through our verifier
    const canonical = refusalClaimHexToBytes(signed.canonicalBytes);
    const sig = refusalClaimHexToBytes(signed.ed25519Sig);
    const verifyResult = verifyRefusalClaim({
      canonicalBytes: canonical,
      ed25519Sig: sig,
      authorityPubkey,
    });

    expect(verifyResult.ok).toBe(true);
    if (!verifyResult.ok) return;
    expect(verifyResult.parsed.reasonCode).toBe(0x06);
    expect(verifyResult.parsed.timestamp).toBe(1716183600n);
  });
});
