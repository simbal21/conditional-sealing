import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  ACTIVE_COMMIT_VERSION,
  COMMIT_AAD_BYTES,
  COMMIT_AAD_DIGEST_PREIMAGE_BYTES,
  computeAADDigest,
  decodeCommitAAD,
  encodeCommitAAD,
  type CommitAADInput,
} from "../../src/codecs/commit-aad.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "commit-aad.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { encoded_bytes: number; aad_digest_preimage_bytes: number; comment: string };
  vectors: Array<{ name: string; input: Record<string, unknown>; encoded_hex: string; aad_digest: string }>;
};

const FIELD_NAMES = [
  "authorizationId",
  "pda_root",
  "schema_digest",
  "partner_id",
  "commit_version",
  "subject_commitment_v3",
  "sigma_subject_digest",
  "recipients_root",
  "p15_attestations_root",
  "endpoint_attestation_digest",
  "conditional_recipients_policy_digest",
  "sdMerkleRoot",
  "g3_choice",
  "phase",
  "composite_identity_type",
  "conditional_recipients_stanza_count",
  "plugin_version_digest",
  "g4_authority_ref",
  "dsl_version_ref",
  "oracle_references_root",
  "superseded_commit_ref",
  "commit_generation",
] as const satisfies readonly (keyof CommitAADInput)[];

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

function inputFromJson(input: Record<string, unknown>): CommitAADInput {
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

function bytes(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, i) => (seed * (i + 1) + i * 19) & 0xff);
}

function fuzzInput(seed: number): CommitAADInput {
  return {
    authorizationId: bytes(seed),
    pda_root: bytes(seed + 1),
    schema_digest: bytes(seed + 2),
    partner_id: bytes(seed + 3),
    commit_version: ACTIVE_COMMIT_VERSION,
    subject_commitment_v3: bytes(seed + 4),
    sigma_subject_digest: bytes(seed + 5),
    recipients_root: bytes(seed + 6),
    p15_attestations_root: bytes(seed + 7),
    endpoint_attestation_digest: bytes(seed + 8),
    conditional_recipients_policy_digest: bytes(seed + 9),
    sdMerkleRoot: seed % 2 === 0 ? new Uint8Array(32) : bytes(seed + 10),
    g3_choice: seed % 2,
    phase: seed % 2 === 0 ? 1 : 2,
    composite_identity_type: 0,
    conditional_recipients_stanza_count: seed * 3,
    plugin_version_digest: bytes(seed + 11),
    g4_authority_ref: bytes(seed + 12),
    dsl_version_ref: bytes(seed + 13),
    oracle_references_root: bytes(seed + 14),
    superseded_commit_ref: seed === 0 ? new Uint8Array(32) : bytes(seed + 15),
    commit_generation: seed,
  };
}

describe("CommitAAD — §4 SCALE codec", () => {
  it("goldens are marked as locked Phase B seeds", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase B seed");
    expect(golden._meta.encoded_bytes).toBe(COMMIT_AAD_BYTES);
    expect(golden._meta.aad_digest_preimage_bytes).toBe(COMMIT_AAD_DIGEST_PREIMAGE_BYTES);
  });

  it("round-trips two canonical fixtures plus eight fuzz inputs", () => {
    const vectors = [...golden.vectors.map((v) => inputFromJson(v.input)), ...Array.from({ length: 8 }, (_, i) => fuzzInput(i + 1))];
    expect(vectors).toHaveLength(10);
    for (const input of vectors) {
      const encoded = encodeCommitAAD(input);
      const decoded = decodeCommitAAD(encoded);
      expect(encodeCommitAAD(decoded)).toEqual(encoded);
      expect(encoded.length).toBe(COMMIT_AAD_BYTES);
    }
  });

  it("matches golden SCALE bytes and aad_digest", () => {
    for (const vector of golden.vectors) {
      const input = inputFromJson(vector.input);
      expect(bytesToHex(encodeCommitAAD(input))).toBe(vector.encoded_hex);
      expect(bytesToHex(computeAADDigest(input))).toBe(vector.aad_digest);
    }
  });

  it("decoder rejects malformed lengths", () => {
    expect(() => decodeCommitAAD(new Uint8Array(COMMIT_AAD_BYTES - 1))).toThrow("ERR_COMMIT_AAD_DECODE_LENGTH");
    expect(() => decodeCommitAAD(new Uint8Array(COMMIT_AAD_BYTES + 1))).toThrow("ERR_COMMIT_AAD_DECODE_LENGTH");
  });

  it("encoder rejects every missing field with typed errors", () => {
    const base = inputFromJson(golden.vectors[0]!.input);
    for (const field of FIELD_NAMES) {
      const bad = { ...base } as Record<string, unknown>;
      delete bad[field];
      expect(() => encodeCommitAAD(bad as unknown as CommitAADInput), field).toThrow("ERR_COMMIT_AAD_MISSING_FIELD");
    }
  });

  it("rejects active-version and enum drift", () => {
    const base = inputFromJson(golden.vectors[0]!.input);
    expect(() => encodeCommitAAD({ ...base, commit_version: 0x0301 })).toThrow("commit_version must be 0x0302");
    expect(() => encodeCommitAAD({ ...base, g3_choice: 2 })).toThrow("g3_choice must be 0 or 1");
    expect(() => encodeCommitAAD({ ...base, phase: 3 })).toThrow("phase must be 1 or 2");
    expect(() => encodeCommitAAD({ ...base, composite_identity_type: 1 })).toThrow("composite_identity_type must be 0");
    expect(() => encodeCommitAAD({ ...base, sdMerkleRoot: new Uint8Array(31) })).toThrow("ERR_COMMIT_AAD_BYTES32_LENGTH");
  });
});
