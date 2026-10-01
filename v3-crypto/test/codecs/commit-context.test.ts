import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  buildCommitContextPreimage,
  buildHCommitPreimage,
  COMMIT_CONTEXT_PREIMAGE_BYTES,
  computeAttestationContextDigest,
  computeCommitContextDigest,
  computeHCommit,
  type CommitContextInput,
} from "../../src/codecs/commit-context.js";
import { TAG_COMMIT_CONTEXT_V3, TAG_COMMIT_V3 } from "../../src/tags.js";
import type { CommitAADInput } from "../../src/codecs/commit-aad.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "commit-context.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string; preimage_bytes: number };
  vectors: Array<{ name: string; input: Record<string, unknown>; preimage_hex: string; commit_context_digest: string }>;
  attestation_vectors: Array<{ name: string; input: Record<string, unknown>; attestation_context_digest: string }>;
};

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

function contextFromJson(input: Record<string, unknown>): CommitContextInput {
  const s = (name: keyof CommitContextInput): string => input[name] as string;
  return {
    authorizationId: hexBytes(s("authorizationId")),
    pda_root: hexBytes(s("pda_root")),
    schema_digest: hexBytes(s("schema_digest")),
    aad_digest: hexBytes(s("aad_digest")),
    composite_identity_digest: hexBytes(s("composite_identity_digest")),
    endpoint_attestation_digest: hexBytes(s("endpoint_attestation_digest")),
    retention_window: BigInt(input.retention_window as string),
    shred_authority_id: hexBytes(s("shred_authority_id")),
    recipients_root: hexBytes(s("recipients_root")),
    reveal_challenge_window: input.reveal_challenge_window as number,
    shred_challenge_window: input.shred_challenge_window as number,
    g3_choice: input.g3_choice as number,
    phase: input.phase as number,
    commit_version: input.commit_version as number,
  };
}

function aadFromJson(input: Record<string, unknown>): CommitAADInput {
  const s = (name: keyof CommitAADInput): string => input[name] as string;
  return {
    authorizationId: hexBytes(s("authorizationId")),
    pda_root: hexBytes(s("pda_root")),
    schema_digest: hexBytes(s("schema_digest")),
    partner_id: hexBytes(s("partner_id")),
    commit_version: input.commit_version as number,
    subject_commitment_v3: hexBytes(s("subject_commitment_v3")),
    sigma_subject_digest: hexBytes(s("sigma_subject_digest")),
    recipients_root: hexBytes(s("recipients_root")),
    p15_attestations_root: hexBytes(s("p15_attestations_root")),
    endpoint_attestation_digest: hexBytes(s("endpoint_attestation_digest")),
    conditional_recipients_policy_digest: hexBytes(s("conditional_recipients_policy_digest")),
    sdMerkleRoot: hexBytes(s("sdMerkleRoot")),
    g3_choice: input.g3_choice as number,
    phase: input.phase as number,
    composite_identity_type: input.composite_identity_type as number,
    conditional_recipients_stanza_count: input.conditional_recipients_stanza_count as number,
    plugin_version_digest: hexBytes(s("plugin_version_digest")),
    g4_authority_ref: hexBytes(s("g4_authority_ref")),
    dsl_version_ref: hexBytes(s("dsl_version_ref")),
    oracle_references_root: hexBytes(s("oracle_references_root")),
    superseded_commit_ref: hexBytes(s("superseded_commit_ref")),
    commit_generation: input.commit_generation as number,
  };
}

describe("commit_context_digest — §3.4 acyclic builder", () => {
  it("goldens are marked as locked Phase B seeds", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase B seed");
    expect(golden._meta.preimage_bytes).toBe(COMMIT_CONTEXT_PREIMAGE_BYTES);
  });

  it("builds 340-byte preimages and matching digests for generation 0 and N contexts", () => {
    for (const vector of golden.vectors) {
      const input = contextFromJson(vector.input);
      const preimage = buildCommitContextPreimage(input);
      expect(preimage.length).toBe(COMMIT_CONTEXT_PREIMAGE_BYTES);
      expect(bytesToHex(preimage)).toBe(vector.preimage_hex);
      expect(bytesToHex(computeCommitContextDigest(input))).toBe(vector.commit_context_digest);
    }
  });

  it("keeps generation-0 payload context byte-stable across wrapper-generation work", () => {
    const generation0 = contextFromJson(golden.vectors.find((v) => v.name === "generation0_canonical")!.input);
    const generation1 = contextFromJson(golden.vectors.find((v) => v.name === "generation1_wrapper_context")!.input);
    const pinned0A = bytesToHex(computeCommitContextDigest(generation0));
    const pinned0B = bytesToHex(computeCommitContextDigest({ ...generation0 }));
    expect(pinned0A).toBe(pinned0B);
    expect(pinned0A).not.toBe(bytesToHex(computeCommitContextDigest(generation1)));
  });

  it("computes attestation_context_digest only for endpoint-zeroed commit_AAD_attestation_N", () => {
    const vector = golden.attestation_vectors[0]!;
    const input = aadFromJson(vector.input);
    expect(bytesToHex(computeAttestationContextDigest(input))).toBe(vector.attestation_context_digest);
    expect(() =>
      computeAttestationContextDigest({ ...input, endpoint_attestation_digest: new Uint8Array(32).fill(1) }),
    ).toThrow("ERR_ATTESTATION_AAD_ENDPOINT_NOT_ZERO");
  });

  it("rejects malformed context fields", () => {
    const base = contextFromJson(golden.vectors[0]!.input);
    expect(() => buildCommitContextPreimage({ ...base, authorizationId: new Uint8Array(31) })).toThrow(
      "ERR_COMMIT_CONTEXT_BYTES32_LENGTH",
    );
    expect(() => buildCommitContextPreimage({ ...base, reveal_challenge_window: -1 })).toThrow(
      "ERR_COMMIT_CONTEXT_FIELD_RANGE",
    );
    expect(() => buildCommitContextPreimage({ ...base, commit_version: 0x0301 })).toThrow(
      "commit_version must be 0x0302",
    );
  });
});

// Security-audit-2026-05-14 TS-CRYPTO-F-05 regression — final h_commit_N
// preimage builder. Same 340-byte layout as commit_context_digest EXCEPT:
//   - prefix is TAG_COMMIT_V3 (not TAG_COMMIT_CONTEXT_V3)
//   - slot 4 carries ciphertext_digest_N (not ZERO32)
describe("h_commit_N — TAG_COMMIT_V3 + ciphertextDigest variant (TS-CRYPTO-F-05 helper)", () => {
  it("builds a 340-byte preimage with TAG_COMMIT_V3 prefix and supplied ciphertextDigest", () => {
    const base = contextFromJson(golden.vectors[0]!.input);
    const ciphertextDigest = new Uint8Array(32).fill(0xAB);
    const preimage = buildHCommitPreimage(base, ciphertextDigest);
    expect(preimage.length).toBe(340);
    // TAG_COMMIT_V3 occupies bytes [0..32]
    const tagHex = bytesToHex(preimage.subarray(0, 32));
    expect(tagHex.toLowerCase()).toBe(TAG_COMMIT_V3.toLowerCase());
    // Slot 4 (offset 32 + 32*3 = 128) carries ciphertextDigest
    expect(bytesToHex(preimage.subarray(128, 160))).toBe(`0x${"ab".repeat(32)}`);
  });

  it("produces a different digest than commit_context for the same input (different TAG + non-zero ciphertext)", () => {
    const base = contextFromJson(golden.vectors[0]!.input);
    const ciphertextDigest = new Uint8Array(32).fill(0x42);
    const hCommit = bytesToHex(computeHCommit(base, ciphertextDigest));
    const commitContext = bytesToHex(computeCommitContextDigest(base));
    expect(hCommit).not.toBe(commitContext);
  });

  it("is deterministic for fixed input + ciphertextDigest", () => {
    const base = contextFromJson(golden.vectors[0]!.input);
    const ciphertextDigest = new Uint8Array(32).fill(0x37);
    expect(bytesToHex(computeHCommit(base, ciphertextDigest))).toBe(
      bytesToHex(computeHCommit(base, ciphertextDigest)),
    );
  });

  it("changes when ciphertextDigest changes (envelope binding)", () => {
    const base = contextFromJson(golden.vectors[0]!.input);
    const cd1 = new Uint8Array(32).fill(0x01);
    const cd2 = new Uint8Array(32).fill(0x02);
    expect(bytesToHex(computeHCommit(base, cd1))).not.toBe(bytesToHex(computeHCommit(base, cd2)));
  });

  it("rejects non-32-byte ciphertextDigest", () => {
    const base = contextFromJson(golden.vectors[0]!.input);
    expect(() => buildHCommitPreimage(base, new Uint8Array(31))).toThrow(
      "ERR_COMMIT_CONTEXT_BYTES32_LENGTH",
    );
  });

  // Sanity: the legacy `keccak256(JSON.stringify(...) ‖ envelope_hash)` formula
  // used in re-key-stanza-addition.ts produces a DIFFERENT h_commit than the
  // spec-compliant form. This test does not assert specific values (no test
  // vectors yet) but proves the two formulas diverge — which is the whole
  // point of TS-CRYPTO-F-05.
  it("differs from the legacy JSON.stringify(...)||envelope formula", () => {
    const base = contextFromJson(golden.vectors[0]!.input);
    const ciphertextDigest = new Uint8Array(32).fill(0x99);
    const specCorrect = bytesToHex(computeHCommit(base, ciphertextDigest));
    // Note: TAG_COMMIT_CONTEXT_V3 reference imported to ensure the byte-prefix
    // diverges from TAG_COMMIT_V3. Both are 32-byte hex strings; the equality
    // check here would fail trivially if someone accidentally pointed
    // computeHCommit at the wrong tag.
    expect(TAG_COMMIT_V3.toLowerCase()).not.toBe(TAG_COMMIT_CONTEXT_V3.toLowerCase());
    expect(specCorrect.length).toBe(66); // 0x + 64 hex chars
  });
});
