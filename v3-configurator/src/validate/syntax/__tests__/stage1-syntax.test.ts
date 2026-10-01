import { describe, expect, it } from "vitest";
import { COMMIT_AAD_FIELD_NAMES } from "../../../types/commit-aad.js";
import { PDA_ROOT_FIELD_NAMES } from "../../../types/pda-root.js";
import { runStage1, type SubmittedPda } from "../index.js";

const HEX = `0x${"11".repeat(32)}`;
const CID = "bafybeigdyrzt5sfp7udm7hu76u4n6v7i2c6h4oxf5kqj4f5b5x3a2z7lqi";

function basePda(): SubmittedPda {
  return {
    schema_version: 1,
    pda_id: HEX,
    pda_version: 1,
    partner_id: "partner_alpha",
    template_id: HEX,
    schema: { fields: [{ path: "subject.age" }, { path: "subject.country" }] },
    schema_mapping: { ageProof: "subject.age" },
    commit_version: 0x0302,
    pda_root_fields: [...PDA_ROOT_FIELD_NAMES],
    commit_aad_fields: [...COMMIT_AAD_FIELD_NAMES],
    reveal_condition: { mode: "P", spec_hash: HEX },
    shred_condition: {
      mode: "P",
      spec_hash: HEX,
      mandatory_guardrail_present: true,
    },
    delivery_mode: "PASSKEY_ACCOUNT",
    trust_tier: "A",
    g3_choice: "dcipher",
    ingestion_mode: "ModeA",
    sd_enabled: true,
    sdMerkleRoot: HEX,
    sd_field_policies: { "subject.age": "zkp" },
    retention_seconds: 31_536_000,
    evidence_cid: CID,
  };
}

describe("@cealis/v3-configurator — Stage 1 syntax (§4.2)", () => {
  it("accepts a syntactically valid submitted PDA", () => {
    expect(runStage1(basePda())).toEqual([]);
  });

  it("emits required-field failures", () => {
    const pda = basePda();
    delete pda["schema"];
    const failures = runStage1(pda);
    expect(failures.some((failure) => failure.stage_code.includes("required_fields_present"))).toBe(true);
  });

  it("rejects unknown fields unless explicit extension metadata is enabled", () => {
    expect(runStage1({ ...basePda(), surprise: true }).map((failure) => failure.internal.surface_name)).toContain(
      "unknown_fields_rejected",
    );
    expect(runStage1({ ...basePda(), schema_version_allows_extension_metadata: true, x_partner_note: true })).toEqual(
      [],
    );
  });

  it("rejects unknown enum identifiers but lets Mode 3 through syntax", () => {
    expect(runStage1({ ...basePda(), trust_tier: "D" }).map((failure) => failure.stage_code)).toEqual(
      expect.arrayContaining([expect.stringContaining("UNKNOWN_ENUM_IDENTIFIER")]),
    );
    expect(runStage1({ ...basePda(), delivery_mode: "WALLET_EIP1271" })).toEqual([]);
  });

  it("rejects non-bytes32 digest values", () => {
    const failures = runStage1({ ...basePda(), pda_id: "0x1234" });
    expect(failures.map((failure) => failure.internal.surface_name)).toContain("bytes32_hex_format");
  });

  it("rejects CID strings that do not parse as expected base32 CIDv1 form", () => {
    const failures = runStage1({ ...basePda(), evidence_cid: "not-a-cid" });
    expect(failures.map((failure) => failure.internal.surface_name)).toContain("cid_parse");
  });

  it("rejects non-integer durations", () => {
    const failures = runStage1({ ...basePda(), retention_seconds: 1.5 });
    expect(failures.map((failure) => failure.internal.surface_name)).toContain("duration_integer_seconds");
  });

  it("rejects PDA JSON that cannot be canonicalized", () => {
    const failures = runStage1({ ...basePda(), retention_seconds: 1n });
    expect(failures.map((failure) => failure.internal.surface_name)).toContain("jcs_round_trip");
  });

  it("rejects schema mapping paths that do not resolve to submitted schema", () => {
    const failures = runStage1({ ...basePda(), schema_mapping: { missing: "subject.address" } });
    expect(failures.map((failure) => failure.internal.surface_name)).toContain(
      "schema_mapping_path_resolves",
    );
  });
});
