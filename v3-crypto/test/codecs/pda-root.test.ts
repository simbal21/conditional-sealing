import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  buildPDARootPreimage,
  computePDARoot,
  zeroPDARootInput,
  type PDARootInput,
} from "../../src/codecs/pda-root.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "pda-root.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  vectors: Array<{ name: string; preimage_hex: string; pda_root: string; input?: Record<string, unknown> }>;
};

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("pda_root — §3.3 builder", () => {
  it("preimage is 540 bytes", () => {
    const preimage = buildPDARootPreimage(zeroPDARootInput());
    expect(preimage.length).toBe(540);
  });

  it("pda_root is 32 bytes (keccak256 output)", () => {
    const root = computePDARoot(zeroPDARootInput());
    expect(root.length).toBe(32);
  });

  it("all-zero golden vector matches", () => {
    const allZero = golden.vectors.find((v) => v.name === "all_zero");
    if (!allZero) throw new Error("missing all_zero golden");
    const preimage = buildPDARootPreimage(zeroPDARootInput());
    const root = computePDARoot(zeroPDARootInput());
    expect(bytesToHex(preimage)).toBe(allZero.preimage_hex);
    expect(bytesToHex(root)).toBe(allZero.pda_root);
  });

  it("canonical_fixture_v1 golden round-trips", () => {
    const fixture = golden.vectors.find((v) => v.name === "canonical_fixture_v1");
    if (!fixture) throw new Error("missing canonical_fixture_v1 golden");

    const fill = (fieldIndex: number): Uint8Array => {
      const out = new Uint8Array(32);
      for (let i = 0; i < 32; i++) out[i] = ((fieldIndex + 1) * (i + 1)) & 0xff;
      return out;
    };

    const input: PDARootInput = {
      pda_id: fill(1),
      pda_version: 2n,
      reveal_condition_mode: 0x02,
      reveal_condition_spec_hash: fill(3),
      shred_condition_mode: 0x02,
      shred_condition_spec_hash: fill(4),
      oracle_references_root: fill(5),
      dsl_version: fill(6),
      wasm_predicate_hashes_root: new Uint8Array(32), // zeroed when unused
      submitter_sets_root: new Uint8Array(32), // zeroed for Mode-P-only
      pause_authority_id: fill(7),
      ceremony_resolver_id: fill(8),
      eligible_challengers_reveal_root: fill(9),
      eligible_challengers_shred_root: fill(10),
      template_id: fill(11),
      partner_id: fill(12),
      subject_authenticator_class: 0x01, // platform_authenticator
      qtsp_provider_ref: new Uint8Array(32), // zeroed when qes_subject_required=false
      art_9_scoped: false,
      art_9_basis_id: 0x00,
      legal_effect_expected: true,
      cealis_class_wide_halt_opt_out: false, // forbidden=true on legal-effect
      minimum_shred_latency: 86400n, // 1 day
      applicable_jurisdiction: fill(13),
      conditional_recipients_updatable: true,
      subject_liveness_required_at_fire: false,
      emergency_response_bricking_acknowledgment: true,
      time_critical_pda_flag: false,
      pda_updatable: true,
    };

    expect(bytesToHex(buildPDARootPreimage(input))).toBe(fixture.preimage_hex);
    expect(bytesToHex(computePDARoot(input))).toBe(fixture.pda_root);
  });

  it("rejects malformed inputs (wrong width / out-of-range)", () => {
    const bad: PDARootInput = { ...zeroPDARootInput(), pda_id: new Uint8Array(31) };
    expect(() => buildPDARootPreimage(bad)).toThrow();

    const oob: PDARootInput = { ...zeroPDARootInput(), reveal_condition_mode: 256 };
    expect(() => buildPDARootPreimage(oob)).toThrow();

    const negVer: PDARootInput = { ...zeroPDARootInput(), pda_version: -1n };
    expect(() => buildPDARootPreimage(negVer)).toThrow();
  });
});
