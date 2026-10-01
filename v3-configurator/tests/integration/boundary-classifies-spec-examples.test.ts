import { describe, expect, it } from "vitest";
import { classifySurface } from "../../src/validate/boundary/index.js";

const CATEGORY_D_EXAMPLES = [
  "sigma_as_authorization",
  "commit_version_0x0302",
  "fixed_gate_set_lit_g3_g4",
  "mode_3_reserved",
  "sd_failure_does_not_block_escrow",
  "two_pipelines_never_cross",
  "no_release_path_bypasses_chain_verified_condition",
  "shamir_single_share_leak_not_dek_leak",
] as const;

const CATEGORY_A_EXAMPLES = [
  "schema_library_membership",
  "fsm_template_library",
  "oracle_registry_admissibility",
  "retention_min_max_bounds",
  "allowed_shred_authority_modes_per_archetype",
  "cross_field_rules",
  "trust_tier_to_oracle_tier_consistency",
  "default_tables",
] as const;

describe("@cealis/v3-configurator — boundary cascade spec examples (§3.2-§3.5)", () => {
  it.each(CATEGORY_D_EXAMPLES)("%s classifies as category (d)", (surface) => {
    const result = classifySurface(surface);
    expect(result.test_exited_on).toBe("1");
    expect(result.category).toBe("(d) architectural fact");
  });

  it("mandatory shred guardrail classifies as Test 1.5 category (a) with derivation pointer", () => {
    const result = classifySurface("mandatory_shred_guardrail");
    expect(result.test_exited_on).toBe("1.5");
    expect(result.category).toBe("(a) PDA+");
    expect(result.derivation_pointer).toBe("universal_tripwire");
  });

  it.each(CATEGORY_A_EXAMPLES)("%s classifies as category (a)", (surface) => {
    const result = classifySurface(surface);
    expect(result.test_exited_on).toBe("2");
    expect(result.category).toBe("(a) PDA+");
  });

  it("discrete and continuous Test 3 examples classify separately", () => {
    expect(classifySurface("delivery_mode").category).toBe("(b) PDA pick");
    expect(classifySurface("challenge_window").category).toBe("(c) PDA parameter");
  });
});
