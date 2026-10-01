import { sha256 } from "@noble/hashes/sha2";
import {
  computePDARoot,
  type Bytes32,
  type PDARootInput,
} from "../m1-imports.js";
import type { PdaRootFields } from "../types/pda-root.js";

const BYTES32_HEX = /^0x[0-9a-fA-F]{64}$/;
const ZERO_HEX = `0x${"00".repeat(32)}`;

export function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function hexToBytes32(value: string): Bytes32 {
  if (!BYTES32_HEX.test(value)) {
    throw new Error(`bytes32: expected 0x-prefixed 32-byte hex, got ${value}`);
  }
  const out = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) {
    out[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return out;
}

export function hashToBytes32(input: unknown): Bytes32 {
  const encoded = new TextEncoder().encode(stableString(input));
  return sha256(encoded);
}

export function hashToHex32(input: unknown): `0x${string}` {
  return bytesToHex(hashToBytes32(input));
}

export function zeroBytes32(): Bytes32 {
  return hexToBytes32(ZERO_HEX);
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return diff === 0;
}

export function buildPdaRootInput(fields: PdaRootFields): PDARootInput {
  return { ...fields };
}

export function computePdaRootFromFields(fields: PdaRootFields): Bytes32 {
  return computePDARoot(buildPdaRootInput(fields));
}

export function derivePdaRootFields(submitted: Record<string, unknown>): PdaRootFields {
  const reveal = recordValue(submitted.reveal_condition);
  const shred = recordValue(submitted.shred_condition);
  const extension = recordValue(submitted.extension_metadata);
  const conditional = recordValue(submitted.conditional_recipients);

  return {
    pda_id: readBytes32(submitted.pda_id, "pda_id"),
    pda_version: toBigInt(submitted.pda_version ?? 1),
    reveal_condition_mode: modeToByte(readString(reveal.mode) ?? "P"),
    reveal_condition_spec_hash: readBytes32(
      reveal.spec_hash ?? reveal.template_pick ?? submitted.template_id,
      "reveal_condition.spec_hash",
    ),
    shred_condition_mode: modeToByte(readString(shred.mode) ?? "P"),
    shred_condition_spec_hash: readBytes32(
      shred.spec_hash ?? submitted.template_id,
      "shred_condition.spec_hash",
    ),
    oracle_references_root: hashToBytes32(reveal.k_of_n ?? reveal.oracle_attestation_refs ?? "oracle:none"),
    dsl_version: hashToBytes32("dsl:v2-configuration"),
    wasm_predicate_hashes_root: hashToBytes32(reveal.module ?? "predicate:none"),
    submitter_sets_root: hashToBytes32(reveal.submitter_sets ?? "submitters:cealis"),
    pause_authority_id: hashToBytes32(extension.shred_authority ?? "pause:none"),
    ceremony_resolver_id: hashToBytes32(extension.ceremony_resolver ?? "resolver:none"),
    eligible_challengers_reveal_root: hashToBytes32(extension.eligible_challengers_reveal ?? "subject"),
    eligible_challengers_shred_root: hashToBytes32(extension.eligible_challengers_shred ?? "operator"),
    template_id: readBytes32(submitted.template_id, "template_id"),
    partner_id: hashToBytes32(submitted.partner_id ?? "partner:unknown"),
    subject_authenticator_class: subjectAuthenticatorClass(extension),
    qtsp_provider_ref: readBytes32(extension.qtsp_provider_ref ?? ZERO_HEX, "qtsp_provider_ref"),
    art_9_scoped: readBoolean(extension.art_9_scoped) ?? false,
    art_9_basis_id: toInteger(extension.art_9_basis_id ?? 0),
    legal_effect_expected: readBoolean(submitted.legal_effect_expected) ?? false,
    cealis_class_wide_halt_opt_out:
      readBoolean(submitted.cealis_class_wide_halt_opt_out) ?? false,
    minimum_shred_latency: toBigInt(
      submitted.minimum_shred_latency_seconds ?? submitted.minimum_shred_latency ?? 0,
    ),
    applicable_jurisdiction: hashToBytes32(extension.applicable_jurisdiction ?? "jurisdiction:none"),
    conditional_recipients_updatable:
      readBoolean(submitted.conditional_recipients_updatable) ??
      readBoolean(conditional.updatable) ??
      readBoolean(extension.conditional_recipients_updatable) ??
      false,
    subject_liveness_required_at_fire:
      readBoolean(submitted.subject_liveness_required_at_fire) ??
      readBoolean(extension.subject_liveness_required_at_fire) ??
      false,
    emergency_response_bricking_acknowledgment:
      readBoolean(submitted.emergency_response_bricking_acknowledgment) ??
      readBoolean(extension.emergency_response_bricking_acknowledgment) ??
      false,
    time_critical_pda_flag:
      readBoolean(submitted.time_critical_pda_flag) ??
      readBoolean(extension.time_critical_pda_flag) ??
      false,
    pda_updatable:
      readBoolean(submitted.pda_updatable) ?? readBoolean(extension.pda_updatable) ?? false,
  };
}

function modeToByte(mode: string): number {
  return mode === "F" ? 0x01 : 0x02;
}

function subjectAuthenticatorClass(extension: Record<string, unknown>): number {
  const value = readString(extension.subject_authenticator_class);
  if (value === "qtsp_qes") return 0x02;
  if (value === "synced_passkey") return 0x03;
  return 0x01;
}

function readBytes32(value: unknown, field: string): Bytes32 {
  if (typeof value === "string" && BYTES32_HEX.test(value)) return hexToBytes32(value);
  if (value === undefined || value === null) return zeroBytes32();
  if (typeof value === "string") return hashToBytes32(value);
  throw new Error(`pda_root: ${field} must be a bytes32 hex string or string seed`);
}

function toBigInt(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  return 0n;
}

function toInteger(value: unknown): number {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return 0;
}

function readString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function readBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stableString(value: unknown): string {
  return JSON.stringify(normalize(value));
}

function normalize(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (Array.isArray(value)) return value.map((entry) => normalize(entry));
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) out[key] = normalize(record[key]);
    return out;
  }
  return null;
}
