// Foundation: partner-readable inspection field set (§7.3).

import { describe, expect, it } from "vitest";
import {
  PARTNER_INSPECTION_FIELD_COUNT,
  PARTNER_INSPECTION_PRIMITIVE_FIELDS,
} from "../../src/types/partner-inspection.js";

describe("@cealis/v3-configurator — partner inspection fields (§7.3)", () => {
  it("PARTNER_INSPECTION_FIELD_COUNT is 28", () => {
    // §7.3 has 17 grouped bullets; decomposing yields 28 primitive
    // fields per the documentation at the top of partner-inspection.ts.
    expect(PARTNER_INSPECTION_FIELD_COUNT).toBe(28);
  });

  it("PARTNER_INSPECTION_PRIMITIVE_FIELDS has 28 entries", () => {
    expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS.length).toBe(28);
  });

  it("includes the bullet-1 fields (partner_id, pda_id, pda_version, pda_root)", () => {
    for (const f of ["partner_id", "pda_id", "pda_version", "pda_root"]) {
      expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS).toContain(f);
    }
  });

  it("includes template + schema fields", () => {
    for (const f of [
      "template_id",
      "template_digest",
      "schema_digest",
      "schema_summary_human_readable",
    ]) {
      expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS).toContain(f);
    }
  });

  it("includes condition summaries", () => {
    for (const f of ["reveal_condition_summary", "shred_condition_summary"]) {
      expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS).toContain(f);
    }
  });

  it("includes trust + custody picks", () => {
    for (const f of ["trust_tier", "oracle_refs", "g3_choice", "g4_phase"]) {
      expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS).toContain(f);
    }
  });

  it("includes recipient summaries + SD audit diff + windows", () => {
    for (const f of [
      "recipients_summary",
      "conditional_recipient_policy_summary",
      "sd_audit_diff_non_escrow_only",
      "retention_windows",
      "challenge_windows",
    ]) {
      expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS).toContain(f);
    }
  });

  it("includes shred + legal fields", () => {
    for (const f of [
      "shred_authority",
      "shred_condition",
      "legal_flags_art9_qes_jurisdiction",
    ]) {
      expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS).toContain(f);
    }
  });

  it("includes class-table classification + defaults + report digests + on-chain refs", () => {
    for (const f of [
      "class_table_classification_per_surface",
      "defaults_applied_with_override_flags",
      "validation_report_digest",
      "simulation_report_digest",
      "ipfs_cids",
      "on_chain_tx_refs",
    ]) {
      expect(PARTNER_INSPECTION_PRIMITIVE_FIELDS).toContain(f);
    }
  });

  it("no duplicate field names", () => {
    const set = new Set(PARTNER_INSPECTION_PRIMITIVE_FIELDS);
    expect(set.size).toBe(PARTNER_INSPECTION_PRIMITIVE_FIELDS.length);
  });
});
