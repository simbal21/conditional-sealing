import { describe, expect, it } from "vitest";
import { ARCHETYPE_NAMES, initTemplate } from "../../src/cli/init.js";
import { validatePDA } from "../../src/pda/emit.js";

describe("CLI init templates", () => {
  it.each(ARCHETYPE_NAMES)("scaffolds %s into a Stage 1-5 valid PDA", (name) => {
    const submitted = initTemplate(name);
    expect(validatePDA(submitted).ok).toBe(true);
  });
});
