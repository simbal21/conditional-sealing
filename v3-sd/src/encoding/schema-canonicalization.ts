import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import type { Bytes32 } from "../tags/preimages.js";
import { fieldTypeCodeFromName, normalizeFieldPath, type FieldTypeName } from "./field-encoding.js";

export interface SchemaField {
  readonly path: string;
  readonly type: FieldTypeName;
  readonly nullable?: boolean;
  readonly max_byte_length?: number;
  readonly numeric_bit_width?: number;
  readonly decimal_scale?: number;
  readonly enum_values?: ReadonlyArray<string>;
}

export interface CanonicalSchemaField {
  readonly path: string;
  readonly type: FieldTypeName;
  readonly type_code: number;
  readonly nullable: boolean;
  readonly max_byte_length?: number;
  readonly numeric_bit_width?: number;
  readonly decimal_scale?: number;
  readonly enum_values?: ReadonlyArray<string>;
  readonly declaration_index: number;
}

export interface SchemaDefinition {
  readonly fields: ReadonlyArray<SchemaField>;
  readonly [key: string]: unknown;
}

export interface CanonicalizedSchema {
  readonly normalized: { readonly fields: ReadonlyArray<CanonicalSchemaField> };
  readonly bytes: Uint8Array;
  readonly digest: Bytes32;
}

export function canonicalizeSchema(schema: SchemaDefinition): CanonicalizedSchema {
  const fields = schema.fields.map((field, declaration_index): CanonicalSchemaField =>
    pruneUndefined({
      path: normalizeFieldPath(field.path),
      type: field.type,
      type_code: fieldTypeCodeFromName(field.type),
      nullable: field.nullable ?? false,
      max_byte_length: field.max_byte_length,
      numeric_bit_width: field.numeric_bit_width,
      decimal_scale: field.decimal_scale,
      enum_values: field.enum_values ? [...field.enum_values] : undefined,
      declaration_index,
    }) as CanonicalSchemaField,
  );
  const normalized = { fields };
  const bytes = utf8ToBytes(canonicalJson(normalized));
  return { normalized, bytes, digest: keccak_256(bytes) };
}

export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  throw new TypeError(`unsupported canonical type: ${typeof value}`);
}

export function readFieldFromPayload(payload: Record<string, unknown>, normalizedPath: string): unknown {
  let current: unknown = payload;
  for (const segment of normalizeFieldPath(normalizedPath).split(".")) {
    if (typeof current !== "object" || current === null || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

export function normalizePayloadAgainstSchema(
  payload: Record<string, unknown>,
  schema: CanonicalizedSchema,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of schema.normalized.fields) out[field.path] = readFieldFromPayload(payload, field.path);
  return out;
}

function pruneUndefined<T extends Record<string, unknown>>(obj: T): Partial<T> {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined)) as Partial<T>;
}
