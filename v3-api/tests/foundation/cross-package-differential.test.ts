import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Cross-package differential — verifies M1+M2+M3+M4 wiring is intact and
// verify-sdk independence is preserved. Per PHASE-PLAN A20.

import * as M1 from "../../src/m1-imports.js";
import * as M3 from "../../src/m3-imports.js";
import * as M4 from "../../src/m4-imports.js";
import { loadArtifact, getRevealAuthorizedEvent } from "../../src/m2-imports.js";

describe("Cross-package differential (Phase A acceptance gate)", () => {
  it("M1 (@cealis/v3-crypto): AEAD + JCS + σ verifiers present", () => {
    expect(typeof M1.computePDARoot).toBe("function");
    expect(typeof M1.verifySigmaLit).toBe("function");
    expect(typeof M1.verifySigmaG3).toBe("function");
    expect(typeof M1.verifySigmaG4).toBe("function");
  });

  it("M2 (Foundry ABI): RevealAuthorized event present + 7 inputs verbatim", () => {
    const art = loadArtifact("ConditionEngine");
    const ev = getRevealAuthorizedEvent(art);
    expect(ev.inputs.length).toBe(7);
  });

  it("M3 (@cealis/v3-custody): all combiner SDK + adapter exports present", () => {
    const expected = [
      "combineAndDecrypt",
      "runPreVerifyPipeline",
      "decryptAeadPayload",
      "assembleRevealArtifactBundle",
      "jcsCanonicalize",
      "jcsDigest",
      "verifyRegistrySnapshots",
      "verifyGateRecipientPubkeys",
      "orchestrateSigmas",
      "rejectMode3",
      "assertShredStateSignable",
      "verifySupersessionLineage",
      "verifyPluginIntegrity",
      "assertCrossVendorTeeDisjoint",
      "applyRuntimeHardening",
      "reconstructFileKey",
      "dispatchProfile",
      "createLitAdapter",
      "createDcipherAdapter",
      "createDrandAdapter",
      "dispatchG3",
      "createG4Phase1Adapter",
      "createG4Phase2Adapter",
    ];
    for (const name of expected) {
      expect(
        (M3 as Record<string, unknown>)[name],
        `M3 missing export: ${name}`,
      ).toBeDefined();
    }
  });

  it("M4 (@cealis/v3-configurator): types catalog present (fixtures deferred to Phase E)", () => {
    expect(M4.PDA_ROOT_FIELD_NAMES.length).toBeGreaterThanOrEqual(28);
    expect(Array.isArray(M4.CATEGORY_VALUES)).toBe(true);
    expect(Array.isArray(M4.AUDIT_TRAIL_FIELD_NAMES)).toBe(true);
    expect(typeof M4.redact).toBe("function");
    // Fixtures themselves: see SPEC-COMPLIANCE-GUARD-M5 §0 — `/fixtures`
    // subpath export is declared in M4 package.json but M4 tsconfig excludes
    // fixtures from compilation, so the dist target is absent at Phase A.
    // Phase E integration tests load via source-file pointer.
  });
});

describe("verify-sdk independence (cross-package — no Cealis runtime deps)", () => {
  it("verify-sdk package.json has zero forbidden deps", () => {
    const pkgPath = resolve(__dirname, "../../../verify-sdk/package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const deps = Object.keys(pkg.dependencies ?? {});
    expect(deps).not.toContain("axios");
    expect(deps).not.toContain("node-fetch");
    expect(deps).not.toContain("@cealis/v3-api");
    expect(deps).not.toContain("@cealis/v3-custody");
    expect(deps).not.toContain("fastify");
    expect(deps).not.toContain("drizzle-orm");
    expect(deps).not.toContain("bullmq");
    // Only the 4 permitted runtime deps.
    expect(deps.sort()).toEqual(
      ["@cealis/v3-crypto", "@noble/hashes", "canonicalize", "viem"].sort(),
    );
  });
});
