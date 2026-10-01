import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { SdError } from "../errors/sd-error.js";
import { SdErrorCode } from "../errors/codes.js";

export const BN254_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const FIELD_TYPE_CODE = {
  string: 0x01,
  uint: 0x02,
  int: 0x03,
  bool: 0x04,
  bytes: 0x05,
  date: 0x06,
  decimal_fixed: 0x07,
  enum: 0x08,
  country_code: 0x09,
  address: 0x0a,
  object_hash: 0x0b,
} as const;

export type FieldTypeName = keyof typeof FIELD_TYPE_CODE;
export type FieldTypeCode = typeof FIELD_TYPE_CODE[FieldTypeName];

export interface EncodeFieldValueOptions {
  readonly max_byte_length?: number;
  readonly numeric_bit_width?: number;
  readonly decimal_scale?: number;
  readonly enum_values?: ReadonlyArray<string>;
  readonly nullable?: boolean;
  readonly field_id_hex?: string;
}

export interface EncodedFieldValue {
  readonly scalar: bigint;
  readonly encoding: FieldTypeName;
  readonly normalized_value: unknown;
  readonly bytes?: Uint8Array;
}

export function concatBytes(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  const total = parts.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function u32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError(`u32: ${value}`);
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function u64be(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) throw new RangeError(`u64: ${value.toString()}`);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

export function os2ip(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) + BigInt(b);
  return acc;
}

export function bigintToBytes32(value: bigint): Uint8Array {
  if (value < 0n || value >= 1n << 256n) throw new RangeError(`uint256: ${value.toString()}`);
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function assertBn254Scalar(value: bigint): void {
  if (value < 0n || value >= BN254_PRIME) {
    throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
  }
}

export function scalarToBytes32(value: bigint): Uint8Array {
  assertBn254Scalar(value);
  return bigintToBytes32(value);
}

export function scalarFromBytesMod(bytes: Uint8Array): bigint {
  return os2ip(bytes) % BN254_PRIME;
}

export function hashToField(bytes: Uint8Array): bigint {
  return os2ip(keccak_256(bytes)) % BN254_PRIME;
}

export function bytes32(input: Uint8Array, label = "bytes32"): Uint8Array {
  if (input.length !== 32) {
    throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, {
      stage: "schema_validation",
      safeRefs: { stage: label, code: SdErrorCode.FIELD_ENCODING_INVALID },
    });
  }
  return new Uint8Array(input);
}

export function hex32(input: Uint8Array): `0x${string}` {
  return `0x${bytesToHex(bytes32(input))}`;
}

export function scalarHex(value: bigint): `0x${string}` {
  return `0x${bytesToHex(scalarToBytes32(value))}`;
}

export function bytesFromHex(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
  }
  return hexToBytes(clean);
}

export function normalizeFieldPath(path: string): string {
  return path
    .normalize("NFC")
    .trim()
    .split(".")
    .map((segment) => segment.trim())
    .filter(Boolean)
    .join(".");
}

export function fieldTypeCodeFromName(type: FieldTypeName | string): FieldTypeCode {
  if (type in FIELD_TYPE_CODE) return FIELD_TYPE_CODE[type as FieldTypeName];
  throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
}

export function fieldTypeNameFromCode(code: number): FieldTypeName {
  const entry = Object.entries(FIELD_TYPE_CODE).find(([, v]) => v === code);
  if (!entry) throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
  return entry[0] as FieldTypeName;
}

export function encodeFieldValue(
  value: unknown,
  field_type_code: number,
  options: EncodeFieldValueOptions = {},
): EncodedFieldValue {
  const type = fieldTypeNameFromCode(field_type_code);
  if (value === null || value === undefined) {
    if (options.nullable === true) return { scalar: 0n, encoding: type, normalized_value: null };
    throw invalidEncoding(options, field_type_code);
  }

  switch (type) {
    case "string": {
      if (typeof value !== "string") throw invalidEncoding(options, field_type_code);
      const bytes = utf8ToBytes(value.normalize("NFC"));
      enforceMaxLength(bytes, options);
      return { scalar: hashToField(bytes), encoding: type, normalized_value: value.normalize("NFC"), bytes };
    }
    case "uint": {
      const n = parseInteger(value);
      if (n < 0n) throw invalidEncoding(options, field_type_code);
      enforceBitWidth(n, options);
      assertBn254Scalar(n);
      return { scalar: n, encoding: type, normalized_value: n.toString() };
    }
    case "int": {
      const n = parseInteger(value);
      const mapped = n >= 0n ? 2n * n : 2n * (-n) - 1n;
      enforceBitWidth(n >= 0n ? n : -n, options);
      assertBn254Scalar(mapped);
      return { scalar: mapped, encoding: type, normalized_value: n.toString() };
    }
    case "bool":
      if (typeof value !== "boolean") throw invalidEncoding(options, field_type_code);
      return { scalar: value ? 1n : 0n, encoding: type, normalized_value: value };
    case "bytes": {
      const bytes = bytesFromUnknown(value);
      enforceMaxLength(bytes, options);
      return { scalar: hashToField(bytes), encoding: type, normalized_value: `0x${bytesToHex(bytes)}`, bytes };
    }
    case "date": {
      const days = parseUnixDay(value);
      assertBn254Scalar(days);
      return { scalar: days, encoding: type, normalized_value: days.toString() };
    }
    case "decimal_fixed": {
      const scaled = parseFixedDecimal(value, options.decimal_scale ?? 0);
      const mapped = scaled >= 0n ? 2n * scaled : 2n * (-scaled) - 1n;
      assertBn254Scalar(mapped);
      return { scalar: mapped, encoding: type, normalized_value: scaled.toString() };
    }
    case "enum": {
      const ordinal = enumOrdinal(value, options.enum_values);
      assertBn254Scalar(ordinal);
      return { scalar: ordinal, encoding: type, normalized_value: ordinal.toString() };
    }
    case "country_code": {
      if (typeof value !== "string") throw invalidEncoding(options, field_type_code);
      const cc = value.normalize("NFC").toUpperCase();
      if (!/^[A-Z]{2}$/.test(cc)) throw invalidEncoding(options, field_type_code);
      return { scalar: (BigInt(cc.charCodeAt(0)) << 8n) + BigInt(cc.charCodeAt(1)), encoding: type, normalized_value: cc };
    }
    case "address": {
      if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw invalidEncoding(options, field_type_code);
      return { scalar: os2ip(bytesFromHex(value)), encoding: type, normalized_value: value.toLowerCase() };
    }
    case "object_hash": {
      const b = typeof value === "string" ? bytesFromHex(value) : value instanceof Uint8Array ? value : undefined;
      if (!b || b.length !== 32) throw invalidEncoding(options, field_type_code);
      return { scalar: scalarFromBytesMod(b), encoding: type, normalized_value: `0x${bytesToHex(b)}`, bytes: b };
    }
  }
}

function invalidEncoding(options: EncodeFieldValueOptions, field_type_code: number): SdError {
  return new SdError(SdErrorCode.FIELD_ENCODING_INVALID, {
    stage: "schema_validation",
    safeRefs: {
      field_id: options.field_id_hex ?? "",
      policy_code: field_type_code,
      code: SdErrorCode.FIELD_ENCODING_INVALID,
    },
  });
}

function enforceMaxLength(bytes: Uint8Array, options: EncodeFieldValueOptions): void {
  if (options.max_byte_length !== undefined && bytes.length > options.max_byte_length) {
    throw invalidEncoding(options, bytes.length);
  }
}

function enforceBitWidth(value: bigint, options: EncodeFieldValueOptions): void {
  if (options.numeric_bit_width === undefined) return;
  if (options.numeric_bit_width <= 0 || options.numeric_bit_width > 253) throw invalidEncoding(options, 0);
  if (value >= 1n << BigInt(options.numeric_bit_width)) throw invalidEncoding(options, options.numeric_bit_width);
}

function parseInteger(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^-?[0-9]+$/.test(value)) return BigInt(value);
  throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
}

function bytesFromUnknown(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (typeof value === "string") return value.startsWith("0x") ? bytesFromHex(value) : utf8ToBytes(value);
  throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
}

function parseUnixDay(value: unknown): bigint {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "string") {
    if (/^[0-9]+$/.test(value)) return BigInt(value);
    if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
      const t = Date.parse(`${value}T00:00:00.000Z`);
      if (!Number.isNaN(t)) return BigInt(Math.floor(t / 86_400_000));
    }
  }
  throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
}

function parseFixedDecimal(value: unknown, scale: number): bigint {
  if (!Number.isInteger(scale) || scale < 0 || scale > 18) throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
  if (typeof value === "bigint") return value * 10n ** BigInt(scale);
  if (typeof value === "number") return parseFixedDecimal(value.toString(), scale);
  if (typeof value !== "string") throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
  const m = /^(-?)([0-9]+)(?:\.([0-9]+))?$/.exec(value);
  if (!m) throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
  const sign = m[1] === "-" ? -1n : 1n;
  const whole = BigInt(m[2] ?? "0");
  const fracRaw = m[3] ?? "";
  if (fracRaw.length > scale) throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
  const frac = BigInt(fracRaw.padEnd(scale, "0") || "0");
  return sign * (whole * 10n ** BigInt(scale) + frac);
}

function enumOrdinal(value: unknown, enumValues?: ReadonlyArray<string>): bigint {
  if (typeof value === "number" && Number.isInteger(value) && value > 0) return BigInt(value);
  if (typeof value === "bigint" && value > 0n) return value;
  if (typeof value === "string" && enumValues) {
    const idx = enumValues.indexOf(value);
    if (idx >= 0) return BigInt(idx + 1);
  }
  throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, { stage: "schema_validation" });
}
