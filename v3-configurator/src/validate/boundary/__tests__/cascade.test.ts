import { describe, expect, it } from "vitest";
import { classifySurface } from "../index.js";

describe("@cealis/v3-configurator — boundary cascade implementation (§3)", () => {
  it("exits Test 1 for cryptographic invariant examples", () => {
    const result = classifySurface("sigma_as_authorization");
    expect(result.test_exited_on).toBe("1");
    expect(result.category).toBe("(d) architectural fact");
  });

  it("exits Test 1.5 with derivation pointer for mandatory shred guardrail", () => {
    const result = classifySurface("mandatory_shred_guardrail");
    expect(result.test_exited_on).toBe("1.5");
    expect(result.category).toBe("(a) PDA+");
    expect(result.derivation_pointer).toBe("universal_tripwire");
  });

  it("exits Test 2 for platform-wide admissibility examples", () => {
    const result = classifySurface("oracle_registry_admissibility");
    expect(result.test_exited_on).toBe("2");
    expect(result.category).toBe("(a) PDA+");
  });

  it("exits Test 3 as category (b) for discrete picks", () => {
    const result = classifySurface("g3_choice");
    expect(result.test_exited_on).toBe("3");
    expect(result.category).toBe("(b) PDA pick");
  });

  it("exits Test 3 as category (c) for continuous values", () => {
    const result = classifySurface("retention_window");
    expect(result.test_exited_on).toBe("3");
    expect(result.category).toBe("(c) PDA parameter");
  });

  it("honors context for future candidate surfaces without mixed exits", () => {
    const result = classifySurface("future_guardrail", {
      invariant_derived_from: "universal_tripwire",
      cross_pda_class_invariant: true,
    });
    expect(result.test_exited_on).toBe("1.5");
    expect(result.category).toBe("(a) PDA+");
    expect(result.derivation_pointer).toBe("universal_tripwire");
  });
});
