import { keccak_256 } from "@noble/hashes/sha3";
import type { Hex32 } from "@cealis/v3-crypto";
import { TAG_G4_ATTESTATION_V3 } from "../m1-imports.js";
import { CUSTODY_ERROR_CODES } from "../errors.js";
import type {
  G4Phase2QuoteStub,
  G4Phase2VerificationContext,
  G4Phase2VerificationResult,
} from "./dcap-quote-types.js";

export function computeG4Phase2UserDataDigest(input: {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
}): Uint8Array {
  return keccak_256(
    concatBytes(
      hexToBytes(TAG_G4_ATTESTATION_V3),
      hexToBytes(input.authorizationId),
      hexToBytes(input.hCommit),
      hexToBytes(input.blockHash),
    ),
  );
}

export function verifyG4Phase2DcapQuote(
  quote: G4Phase2QuoteStub,
  context: G4Phase2VerificationContext,
): G4Phase2VerificationResult {
  const expectedUserData = computeG4Phase2UserDataDigest(context);
  if (!startsWithBytes(quote.userData, expectedUserData) || !isZeroPadded(quote.userData, expectedUserData.length)) {
    return fail(quote, "ERR_SIGMA_G4_PHASE2_USER_DATA_MISMATCH");
  }
  if (!quote.tcbAccepted) return fail(quote, "ERR_SIGMA_G4_PHASE2_DCAP_INVALID");
  if (quote.measurement !== context.expectedMeasurement) {
    return fail(quote, "ERR_SIGMA_G4_PHASE2_DCAP_INVALID");
  }
  if (quote.verifierRef !== context.expectedVerifierRef) {
    return fail(quote, CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_DCAP_INVALID);
  }
  return {
    ok: true,
    quoteDigest: quote.quoteDigest,
    vendorFamily: quote.vendorFamily,
    measurement: quote.measurement,
    verifierRef: quote.verifierRef,
  };
}

function fail(quote: G4Phase2QuoteStub, code: string): G4Phase2VerificationResult {
  return {
    ok: false,
    quoteDigest: quote.quoteDigest,
    vendorFamily: quote.vendorFamily,
    measurement: quote.measurement,
    verifierRef: quote.verifierRef,
    code,
  };
}

function startsWithBytes(value: Uint8Array, prefix: Uint8Array): boolean {
  if (value.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (value[i] !== prefix[i]) return false;
  }
  return true;
}

function isZeroPadded(value: Uint8Array, start: number): boolean {
  for (let i = start; i < value.length; i++) {
    if (value[i] !== 0) return false;
  }
  return true;
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function hexToBytes(hex: Hex32): Uint8Array {
  const stripped = hex.slice(2);
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  return out;
}
