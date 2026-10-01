import type { Hex32 } from "@cealis/v3-crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { SigmaBuffer } from "../redaction/sigma-buffer.js";
import {
  bytesToHex,
  canonicalizeAcc,
  hexToBytes,
  type JsonValue,
} from "./acc-canonicalize.js";
import type { TeeVendorEvidence } from "./vendor-family-normalize.js";

export interface LitDcapQuote {
  readonly quoteId: string;
  readonly quoteVersion: string;
  readonly vendor: TeeVendorEvidence;
  readonly assignedTeeId: Hex32;
  readonly measurementDigest: Hex32;
  readonly userData: Uint8Array;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly tcbStatus: string;
  readonly signatureChainValid: boolean;
  readonly collateralFresh: boolean;
  readonly enclaveMeasurementMatches: boolean;
  readonly bindingStatementDigests: readonly Hex32[];
}

export type LitDcapQuoteInput = SigmaBuffer | Uint8Array | string | Record<string, unknown>;

export function parseLitDcapQuote(input: LitDcapQuoteInput): LitDcapQuote {
  const raw = input instanceof SigmaBuffer ? input.unwrap() : input;
  const decoded = raw instanceof Uint8Array ? JSON.parse(new TextDecoder().decode(raw)) : typeof raw === "string" ? JSON.parse(raw) : raw;
  const obj = decoded as Record<string, unknown>;
  const vendor = readVendor(obj.vendor);
  const userDataHex = readString(obj, "userData");
  const bindingStatementDigests = readStringArray(obj.bindingStatementDigests ?? []);

  return {
    quoteId: readString(obj, "quoteId"),
    quoteVersion: readString(obj, "quoteVersion"),
    vendor,
    assignedTeeId: readHex32(obj, "assignedTeeId"),
    measurementDigest: readHex32(obj, "measurementDigest"),
    userData: hexToBytes(userDataHex),
    issuedAtMs: readNumber(obj, "issuedAtMs"),
    expiresAtMs: readNumber(obj, "expiresAtMs"),
    tcbStatus: readString(obj, "tcbStatus"),
    signatureChainValid: readBoolean(obj, "signatureChainValid"),
    collateralFresh: readBoolean(obj, "collateralFresh"),
    enclaveMeasurementMatches: readBoolean(obj, "enclaveMeasurementMatches"),
    bindingStatementDigests,
  };
}

export function litDcapQuoteDigest(input: LitDcapQuoteInput): Hex32 {
  const raw = input instanceof SigmaBuffer ? input.unwrap() : input;
  if (raw instanceof Uint8Array) return bytesToHex(keccak_256(raw));
  if (typeof raw === "string") return bytesToHex(keccak_256(new TextEncoder().encode(raw)));
  return bytesToHex(keccak_256(canonicalizeAcc(raw as JsonValue)));
}

function readVendor(value: unknown): TeeVendorEvidence {
  if (typeof value !== "object" || value === null) return {};
  const obj = value as Record<string, unknown>;
  return {
    vendorRoot: typeof obj.vendorRoot === "string" ? obj.vendorRoot : undefined,
    isolationTechnology: typeof obj.isolationTechnology === "string" ? obj.isolationTechnology : undefined,
    productName: typeof obj.productName === "string" ? obj.productName : undefined,
    measurementFormat: typeof obj.measurementFormat === "string" ? obj.measurementFormat : undefined,
  };
}

function readString(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value.length === 0) throw new Error(`DCAP quote missing string ${key}`);
  return value;
}

function readHex32(obj: Record<string, unknown>, key: string): Hex32 {
  const value = readString(obj, key);
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`DCAP quote ${key} must be bytes32`);
  return value as Hex32;
}

function readNumber(obj: Record<string, unknown>, key: string): number {
  const value = obj[key];
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`DCAP quote missing number ${key}`);
  return value;
}

function readBoolean(obj: Record<string, unknown>, key: string): boolean {
  const value = obj[key];
  if (typeof value !== "boolean") throw new Error(`DCAP quote missing boolean ${key}`);
  return value;
}

function readStringArray(value: unknown): readonly Hex32[] {
  if (!Array.isArray(value)) throw new Error("DCAP quote bindingStatementDigests must be an array");
  return value.map((entry) => {
    if (typeof entry !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(entry)) {
      throw new Error("DCAP quote binding statement digest must be bytes32");
    }
    return entry as Hex32;
  });
}
