import { keccak_256 } from "@noble/hashes/sha3";
import type { Hex32 } from "@cealis/v3-crypto";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";
import { bytesToHex, concatBytes, hexToBytes32 } from "./acc-canonicalize.js";
import {
  litDcapQuoteDigest,
  parseLitDcapQuote,
  type LitDcapQuoteInput,
} from "./dcap-quote.js";
import {
  normalizeVendorFamily,
  type VendorFamilyResult,
} from "./vendor-family-normalize.js";

export interface VerifyLitDcapQuoteInput {
  readonly quote: LitDcapQuoteInput;
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
  readonly nowMs?: number;
  readonly maxQuoteAgeMs?: number;
  readonly acceptedTcbStatuses?: readonly string[];
  readonly expectedMeasurementDigest?: Hex32;
}

export interface LitDcapVerification {
  readonly quoteDigest: Hex32;
  readonly assignedTeeId: Hex32;
  readonly measurementDigest: Hex32;
  readonly quoteVersion: string;
  readonly vendorFamily: VendorFamilyResult;
  readonly bindingStatementDigests: readonly Hex32[];
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

export function computeLitUserDataDigest(input: {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
}): Uint8Array {
  return keccak_256(
    concatBytes([
      hexToBytes32(input.authorizationId),
      hexToBytes32(input.hCommit),
      hexToBytes32(input.blockHash),
    ]),
  );
}

export function computeLitUserData(input: {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
}): Uint8Array {
  const out = new Uint8Array(64);
  out.set(computeLitUserDataDigest(input), 0);
  return out;
}

export function verifyLitDcapQuote(input: VerifyLitDcapQuoteInput): LitDcapVerification {
  let quote;
  try {
    quote = parseLitDcapQuote(input.quote);
  } catch (err) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_DCAP_INVALID,
      "Lit DCAP quote parse failed",
      { cause: err },
    );
  }

  if (quote.userData.length !== 64) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_DCAP_INVALID,
      "Lit DCAP quote user_data must be 64 bytes",
    );
  }
  const expectedUserData = computeLitUserData(input);
  if (!bytesEqual(quote.userData, expectedUserData)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_QUOTE_REPLAY,
      "Lit DCAP quote user_data is not bound to this authorization tuple",
    );
  }
  if (!quote.signatureChainValid || !quote.collateralFresh || !quote.enclaveMeasurementMatches) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_DCAP_INVALID,
      "Lit DCAP quote signature chain, collateral, or measurement check failed",
    );
  }
  if (input.expectedMeasurementDigest !== undefined && quote.measurementDigest !== input.expectedMeasurementDigest) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_DCAP_INVALID,
      "Lit DCAP quote measurement digest does not match assignment metadata",
    );
  }

  const accepted = new Set(input.acceptedTcbStatuses ?? ["OK", "UP_TO_DATE"]);
  if (!accepted.has(quote.tcbStatus)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_DCAP_INVALID,
      `Lit DCAP quote TCB status ${quote.tcbStatus} not accepted`,
    );
  }

  const nowMs = input.nowMs ?? Date.now();
  const maxQuoteAgeMs = input.maxQuoteAgeMs ?? 5 * 60 * 1000;
  if (quote.issuedAtMs > nowMs + 30_000 || quote.expiresAtMs < nowMs || nowMs - quote.issuedAtMs > maxQuoteAgeMs) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_DCAP_INVALID,
      "Lit DCAP quote freshness check failed",
    );
  }

  return {
    quoteDigest: litDcapQuoteDigest(input.quote),
    assignedTeeId: quote.assignedTeeId,
    measurementDigest: quote.measurementDigest,
    quoteVersion: quote.quoteVersion,
    vendorFamily: normalizeVendorFamily(quote.vendor),
    bindingStatementDigests: quote.bindingStatementDigests,
    issuedAtMs: quote.issuedAtMs,
    expiresAtMs: quote.expiresAtMs,
  };
}

export function litUserDataHex(input: {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
}): `0x${string}` {
  return bytesToHex(computeLitUserData(input));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
