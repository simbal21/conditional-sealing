// pda_root builder per docs/specs/cryptography-spec.md §3.3 (29 fields D1-locked).
//
// Construction: keccak256(TAG_PDA_ROOT_V3 ‖ <29 fixed-width fields>) → 32 bytes.
// Preimage: 540 bytes total (32 TAG + 13×32 bytes32 + 8 pda_version u64 BE
// + 1+1 enum modes + 1 subject_authenticator_class + 32 qtsp_provider_ref
// + 1 art_9_scoped + 1 art_9_basis_id + 1 legal_effect_expected
// + 1 cealis_class_wide_halt_opt_out + 8 minimum_shred_latency
// + 32 applicable_jurisdiction + 5×1 boolean tail).
//
// Encoding: byte-concat (NOT SCALE) per §3.3.2. The conditional binding rule
// (D1 normative): every field MUST appear in the preimage regardless of value;
// "not applicable" semantics use the zero-value of the field's type.

import { keccak_256 } from "@noble/hashes/sha3";
import { TAG_PDA_ROOT_V3, type Hex32 } from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";

/**
 * Inputs for `pda_root` derivation per §3.3.3 (16 original) + §3.3.4 (13 D1).
 *
 * All bytes32 fields are 32-byte Uint8Arrays. Booleans are 0/1 byte values.
 * Enums are uint8 values. uint64 fields are bigint values (BE encoded).
 *
 * Per §3.3.2 conditional binding rule, fields that aren't semantically active
 * for a given PDA configuration MUST still be included with zero-valued bytes.
 */
export interface PDARootInput {
  // §3.3.3 — original 16 fields
  pda_id: Bytes32;
  pda_version: bigint; // uint64 BE
  reveal_condition_mode: number; // 0x01 Mode F | 0x02 Mode P
  reveal_condition_spec_hash: Bytes32;
  shred_condition_mode: number; // 0x01 Mode F | 0x02 Mode P
  shred_condition_spec_hash: Bytes32;
  oracle_references_root: Bytes32;
  dsl_version: Bytes32;
  wasm_predicate_hashes_root: Bytes32;
  submitter_sets_root: Bytes32;
  pause_authority_id: Bytes32;
  ceremony_resolver_id: Bytes32;
  eligible_challengers_reveal_root: Bytes32;
  eligible_challengers_shred_root: Bytes32;
  template_id: Bytes32;
  partner_id: Bytes32;

  // §3.3.4 — 13 D1 additions
  subject_authenticator_class: number; // 0x01 platform | 0x02 qtsp_qes | 0x03 synced_passkey
  qtsp_provider_ref: Bytes32; // zeroed when qes_subject_required=false
  art_9_scoped: boolean;
  art_9_basis_id: number; // 0x00 when art_9_scoped=false
  legal_effect_expected: boolean;
  cealis_class_wide_halt_opt_out: boolean; // forbidden=true on legal-effect PDAs
  minimum_shred_latency: bigint; // uint64 seconds BE
  applicable_jurisdiction: Bytes32; // scalar code or merkle root
  conditional_recipients_updatable: boolean;
  subject_liveness_required_at_fire: boolean;
  emergency_response_bricking_acknowledgment: boolean;
  time_critical_pda_flag: boolean;
  pda_updatable: boolean;
}

const PREIMAGE_BYTES = 540;

function assertBytes32(name: string, value: Bytes): void {
  if (value.length !== 32) {
    throw new Error(`pda_root: field ${name} must be 32 bytes, got ${value.length}`);
  }
}

function assertU8Range(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new Error(`pda_root: field ${name} must be uint8 (0..255), got ${value}`);
  }
}

function u64BE(value: bigint, name: string): Bytes {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`pda_root: field ${name} must be uint64 (0..2^64-1), got ${value}`);
  }
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function boolByte(value: boolean): Bytes {
  return new Uint8Array([value ? 0x01 : 0x00]);
}

function tagToBytes(tag: Hex32): Bytes {
  // strip "0x" then hex-decode 32 bytes
  const hex = tag.slice(2);
  if (hex.length !== 64) throw new Error(`tag must be 32 bytes hex, got length ${hex.length}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Build the 540-byte pda_root preimage for §3.3.1, in canonical concat order.
 *
 * Exposed for testing + cross-impl verification. Production callers use
 * `computePDARoot()` instead.
 */
export function buildPDARootPreimage(input: PDARootInput): Bytes {
  // Validate widths up-front so a single failed assertion catches drift
  // rather than silently producing a short preimage.
  const b32 = [
    ["pda_id", input.pda_id],
    ["reveal_condition_spec_hash", input.reveal_condition_spec_hash],
    ["shred_condition_spec_hash", input.shred_condition_spec_hash],
    ["oracle_references_root", input.oracle_references_root],
    ["dsl_version", input.dsl_version],
    ["wasm_predicate_hashes_root", input.wasm_predicate_hashes_root],
    ["submitter_sets_root", input.submitter_sets_root],
    ["pause_authority_id", input.pause_authority_id],
    ["ceremony_resolver_id", input.ceremony_resolver_id],
    ["eligible_challengers_reveal_root", input.eligible_challengers_reveal_root],
    ["eligible_challengers_shred_root", input.eligible_challengers_shred_root],
    ["template_id", input.template_id],
    ["partner_id", input.partner_id],
    ["qtsp_provider_ref", input.qtsp_provider_ref],
    ["applicable_jurisdiction", input.applicable_jurisdiction],
  ] as const;
  for (const [name, value] of b32) assertBytes32(name, value);
  assertU8Range("reveal_condition_mode", input.reveal_condition_mode);
  assertU8Range("shred_condition_mode", input.shred_condition_mode);
  assertU8Range("subject_authenticator_class", input.subject_authenticator_class);
  assertU8Range("art_9_basis_id", input.art_9_basis_id);

  const out = new Uint8Array(PREIMAGE_BYTES);
  let off = 0;
  const writeBytes = (value: Bytes): void => {
    out.set(value, off);
    off += value.length;
  };

  // 32 — TAG_PDA_ROOT_V3
  writeBytes(tagToBytes(TAG_PDA_ROOT_V3));

  // 16 original fields per §3.3.3
  writeBytes(input.pda_id);
  writeBytes(u64BE(input.pda_version, "pda_version"));
  out[off++] = input.reveal_condition_mode;
  writeBytes(input.reveal_condition_spec_hash);
  out[off++] = input.shred_condition_mode;
  writeBytes(input.shred_condition_spec_hash);
  writeBytes(input.oracle_references_root);
  writeBytes(input.dsl_version);
  writeBytes(input.wasm_predicate_hashes_root);
  writeBytes(input.submitter_sets_root);
  writeBytes(input.pause_authority_id);
  writeBytes(input.ceremony_resolver_id);
  writeBytes(input.eligible_challengers_reveal_root);
  writeBytes(input.eligible_challengers_shred_root);
  writeBytes(input.template_id);
  writeBytes(input.partner_id);

  // 13 D1 additions per §3.3.4
  out[off++] = input.subject_authenticator_class;
  writeBytes(input.qtsp_provider_ref);
  writeBytes(boolByte(input.art_9_scoped));
  out[off++] = input.art_9_basis_id;
  writeBytes(boolByte(input.legal_effect_expected));
  writeBytes(boolByte(input.cealis_class_wide_halt_opt_out));
  writeBytes(u64BE(input.minimum_shred_latency, "minimum_shred_latency"));
  writeBytes(input.applicable_jurisdiction);
  writeBytes(boolByte(input.conditional_recipients_updatable));
  writeBytes(boolByte(input.subject_liveness_required_at_fire));
  writeBytes(boolByte(input.emergency_response_bricking_acknowledgment));
  writeBytes(boolByte(input.time_critical_pda_flag));
  writeBytes(boolByte(input.pda_updatable));

  if (off !== PREIMAGE_BYTES) {
    throw new Error(`pda_root preimage length mismatch: wrote ${off}, expected ${PREIMAGE_BYTES}`);
  }
  return out;
}

/**
 * Compute pda_root = keccak256(TAG_PDA_ROOT_V3 ‖ <29 fixed-width fields>).
 * Returns a 32-byte digest.
 */
export function computePDARoot(input: PDARootInput): Bytes32 {
  return keccak_256(buildPDARootPreimage(input));
}

/** All-zero PDARootInput. Useful for tests + canonical-zero golden vector. */
export function zeroPDARootInput(): PDARootInput {
  const z32 = (): Bytes32 => new Uint8Array(32);
  return {
    pda_id: z32(),
    pda_version: 0n,
    reveal_condition_mode: 0,
    reveal_condition_spec_hash: z32(),
    shred_condition_mode: 0,
    shred_condition_spec_hash: z32(),
    oracle_references_root: z32(),
    dsl_version: z32(),
    wasm_predicate_hashes_root: z32(),
    submitter_sets_root: z32(),
    pause_authority_id: z32(),
    ceremony_resolver_id: z32(),
    eligible_challengers_reveal_root: z32(),
    eligible_challengers_shred_root: z32(),
    template_id: z32(),
    partner_id: z32(),
    subject_authenticator_class: 0,
    qtsp_provider_ref: z32(),
    art_9_scoped: false,
    art_9_basis_id: 0,
    legal_effect_expected: false,
    cealis_class_wide_halt_opt_out: false,
    minimum_shred_latency: 0n,
    applicable_jurisdiction: z32(),
    conditional_recipients_updatable: false,
    subject_liveness_required_at_fire: false,
    emergency_response_bricking_acknowledgment: false,
    time_critical_pda_flag: false,
    pda_updatable: false,
  };
}
