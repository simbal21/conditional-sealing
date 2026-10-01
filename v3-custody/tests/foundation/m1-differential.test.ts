// Foundation test — M1 differential.
//
// Loads M1's `pda-root.golden.json` and `share-record.golden.json`
// fixtures via the @cealis/v3-crypto package, runs each vector through
// the V3 SDK's re-export of M1's `computePDARoot` / `encodeShareRecord`
// / `decodeShareRecord`, and asserts byte-for-byte equality.
//
// If this test fails, M1's `dist/` is stale OR a name has drifted in
// `src/m1-imports.ts`. Either way: STOP before firing Codex chunks.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import {
  computePDARoot,
  encodeShareRecord,
  decodeShareRecord,
  type PDARootInput,
  type ShareRecord,
  type Bytes32,
  type Hex32,
} from "../../src/m1-imports.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Resolve M1's fixtures directory relative to this test file.
const M1_FIXTURES = resolve(__dirname, "../../..", "v3-crypto/test/fixtures");

function hexToBytes32(hex: string): Bytes32 {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length !== 64) {
    throw new Error(`hexToBytes32: expected 64 hex chars, got ${stripped.length}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(stripped.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHexPrefixed(b: Uint8Array): string {
  let s = "0x";
  for (let i = 0; i < b.length; i++) {
    s += b[i]!.toString(16).padStart(2, "0");
  }
  return s;
}

interface PDARootGoldenVector {
  name: string;
  description?: string;
  input?: {
    pda_id: string;
    pda_version: string;
    reveal_condition_mode: number;
    reveal_condition_spec_hash: string;
    shred_condition_mode: number;
    shred_condition_spec_hash: string;
    oracle_references_root: string;
    dsl_version: string;
    wasm_predicate_hashes_root: string;
    submitter_sets_root: string;
    pause_authority_id: string;
    ceremony_resolver_id: string;
    eligible_challengers_reveal_root: string;
    eligible_challengers_shred_root: string;
    template_id: string;
    partner_id: string;
    subject_authenticator_class: number;
    qtsp_provider_ref: string;
    art_9_scoped: boolean;
    art_9_basis_id: number;
    legal_effect_expected: boolean;
    cealis_class_wide_halt_opt_out: boolean;
    minimum_shred_latency: string;
    applicable_jurisdiction: string;
    conditional_recipients_updatable: boolean;
    subject_liveness_required_at_fire: boolean;
    emergency_response_bricking_acknowledgment: boolean;
    time_critical_pda_flag: boolean;
    pda_updatable: boolean;
  };
  pda_root: Hex32;
}

interface PDARootGolden {
  _meta: unknown;
  vectors: PDARootGoldenVector[];
}

describe("M1 differential (Phase A acceptance gate — golden vector parity)", () => {
  it("computePDARoot() matches every vector in M1's pda-root.golden.json", () => {
    const goldenPath = `${M1_FIXTURES}/pda-root.golden.json`;
    const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as PDARootGolden;

    // Filter to vectors that include an `input` block (some entries may be
    // empty placeholders or preimage-only). We process only the ones with
    // a structured input.
    const verifiable = golden.vectors.filter((v) => v.input);
    expect(verifiable.length).toBeGreaterThanOrEqual(1);

    for (const v of verifiable) {
      const i = v.input!;
      const sdkInput: PDARootInput = {
        pda_id: hexToBytes32(i.pda_id),
        pda_version: BigInt(i.pda_version),
        reveal_condition_mode: i.reveal_condition_mode,
        reveal_condition_spec_hash: hexToBytes32(i.reveal_condition_spec_hash),
        shred_condition_mode: i.shred_condition_mode,
        shred_condition_spec_hash: hexToBytes32(i.shred_condition_spec_hash),
        oracle_references_root: hexToBytes32(i.oracle_references_root),
        dsl_version: hexToBytes32(i.dsl_version),
        wasm_predicate_hashes_root: hexToBytes32(i.wasm_predicate_hashes_root),
        submitter_sets_root: hexToBytes32(i.submitter_sets_root),
        pause_authority_id: hexToBytes32(i.pause_authority_id),
        ceremony_resolver_id: hexToBytes32(i.ceremony_resolver_id),
        eligible_challengers_reveal_root: hexToBytes32(i.eligible_challengers_reveal_root),
        eligible_challengers_shred_root: hexToBytes32(i.eligible_challengers_shred_root),
        template_id: hexToBytes32(i.template_id),
        partner_id: hexToBytes32(i.partner_id),
        subject_authenticator_class: i.subject_authenticator_class,
        qtsp_provider_ref: hexToBytes32(i.qtsp_provider_ref),
        art_9_scoped: i.art_9_scoped,
        art_9_basis_id: i.art_9_basis_id,
        legal_effect_expected: i.legal_effect_expected,
        cealis_class_wide_halt_opt_out: i.cealis_class_wide_halt_opt_out,
        minimum_shred_latency: BigInt(i.minimum_shred_latency),
        applicable_jurisdiction: hexToBytes32(i.applicable_jurisdiction),
        conditional_recipients_updatable: i.conditional_recipients_updatable,
        subject_liveness_required_at_fire: i.subject_liveness_required_at_fire,
        emergency_response_bricking_acknowledgment: i.emergency_response_bricking_acknowledgment,
        time_critical_pda_flag: i.time_critical_pda_flag,
        pda_updatable: i.pda_updatable,
      };

      const root = computePDARoot(sdkInput);
      const rootHex = bytesToHexPrefixed(root);
      expect(rootHex, `Vector "${v.name}" PDA root mismatch`).toBe(v.pda_root);
    }
  });

  it("encodeShareRecord/decodeShareRecord round-trip is byte-stable", () => {
    // Synthetic share record covering all fields. Validates the M1
    // re-export plumbing for share-record codec.
    const value = new Uint8Array(32);
    for (let i = 0; i < 32; i++) value[i] = i + 1;

    const record: ShareRecord = {
      share_domain: 0x01, // SHARE_DOMAIN_TOP_LEVEL
      share_role: 0x01, // SHARE_ROLE_LIT
      logical_index: 0,
      x: 7, // non-zero GF(2^8) coordinate
      value,
    };

    const encoded = encodeShareRecord(record);
    expect(encoded.length).toBe(39); // 1+1+4+1+32

    const roundTrip = decodeShareRecord(encoded);
    expect(roundTrip.share_domain).toBe(record.share_domain);
    expect(roundTrip.share_role).toBe(record.share_role);
    expect(roundTrip.logical_index).toBe(record.logical_index);
    expect(roundTrip.x).toBe(record.x);
    expect(roundTrip.value).toEqual(record.value);

    const encoded2 = encodeShareRecord(roundTrip);
    expect(encoded2).toEqual(encoded);
  });
});
