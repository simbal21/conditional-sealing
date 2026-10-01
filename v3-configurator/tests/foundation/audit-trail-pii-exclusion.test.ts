// Foundation: audit trail PII exclusion (§1.4).

import { describe, expect, it } from "vitest";
import {
  AUDIT_TRAIL_FIELD_COUNT,
  AUDIT_TRAIL_FIELD_NAMES,
  findPiiMatch,
  PII_EXCLUSION_PATTERNS,
} from "../../src/types/audit-trail.js";

describe("@cealis/v3-configurator — audit trail PII exclusion (§1.4)", () => {
  it("AUDIT_TRAIL_FIELD_COUNT is 10", () => {
    expect(AUDIT_TRAIL_FIELD_COUNT).toBe(10);
  });

  it("AUDIT_TRAIL_FIELD_NAMES has 10 entries", () => {
    expect(AUDIT_TRAIL_FIELD_NAMES.length).toBe(10);
  });

  it("AUDIT_TRAIL_FIELD_NAMES covers the 9 spec-named fields + recorded_at", () => {
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("input_form_digest");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("translated_pda_json_digest");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("template_ids");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("validation_result_set");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("simulation_result_digest");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("human_reviewer_identity_digest");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("emitted_pda_root");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("ipfs_cids");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("on_chain_tx_refs");
    expect(AUDIT_TRAIL_FIELD_NAMES).toContain("recorded_at_unix_seconds");
  });

  it("PII_EXCLUSION_PATTERNS includes σ-as-authorization markers", () => {
    expect(PII_EXCLUSION_PATTERNS).toContain("sigma_lit");
    expect(PII_EXCLUSION_PATTERNS).toContain("sigma_g3");
    expect(PII_EXCLUSION_PATTERNS).toContain("sigma_g4");
    expect(PII_EXCLUSION_PATTERNS).toContain("sigma_subject");
  });

  it("PII_EXCLUSION_PATTERNS includes Shamir / DEK / SD-salt / raw-KYC", () => {
    expect(PII_EXCLUSION_PATTERNS).toContain("shamir_share");
    expect(PII_EXCLUSION_PATTERNS).toContain("shamir_secret");
    expect(PII_EXCLUSION_PATTERNS).toContain("dek_raw");
    expect(PII_EXCLUSION_PATTERNS).toContain("hkdf_ikm");
    expect(PII_EXCLUSION_PATTERNS).toContain("sd_salt");
    expect(PII_EXCLUSION_PATTERNS).toContain("raw_kyc");
    expect(PII_EXCLUSION_PATTERNS).toContain("plaintext_pii");
  });

  it("PII_EXCLUSION_PATTERNS includes plaintext refusal reasons for 0x02 / 0x03", () => {
    expect(PII_EXCLUSION_PATTERNS).toContain("refusal_reason_plaintext_0x02");
    expect(PII_EXCLUSION_PATTERNS).toContain("refusal_reason_plaintext_0x03");
  });

  it("findPiiMatch detects every PII pattern", () => {
    for (const pat of PII_EXCLUSION_PATTERNS) {
      const match = findPiiMatch(`{ "leak": "${pat}" }`);
      expect(match, `pattern ${pat} must be detected`).toBe(pat);
    }
  });

  it("findPiiMatch returns null for clean strings", () => {
    expect(findPiiMatch("audit trail clean record")).toBeNull();
    expect(findPiiMatch('{ "field": "input_form_digest" }')).toBeNull();
  });

  it("AUDIT_TRAIL_FIELD_NAMES contains no PII pattern substrings", () => {
    for (const fieldName of AUDIT_TRAIL_FIELD_NAMES) {
      const match = findPiiMatch(fieldName);
      expect(
        match,
        `audit trail field "${fieldName}" must NOT match a PII pattern`,
      ).toBeNull();
    }
  });
});
