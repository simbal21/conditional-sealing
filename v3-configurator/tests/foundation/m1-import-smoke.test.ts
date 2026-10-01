// Foundation: M1 facade smoke test.
//
// Per PHASE-PLAN A2: "Smoke test re-runs M1's pda-root golden vector (or
// equivalent) via the facade and asserts hex digest matches. Single
// Phase-A file removes Codex's reason to invoke @noble/curves directly
// inside src/pda/; smoke test fails LOUDLY if M1's dist/ is stale or
// export name drifted."

import { describe, expect, it } from "vitest";
import {
  computePDARoot,
  buildPDARootPreimage,
  zeroPDARootInput,
  TAG_PDA_ROOT_V3,
  TAG_COMMIT_V3,
  TAG_AAD_V3,
} from "../../src/m1-imports.js";

describe("@cealis/v3-configurator — M1 facade smoke", () => {
  it("re-exports computePDARoot from @cealis/v3-crypto", () => {
    expect(typeof computePDARoot).toBe("function");
  });

  it("re-exports buildPDARootPreimage from @cealis/v3-crypto", () => {
    expect(typeof buildPDARootPreimage).toBe("function");
  });

  it("re-exports zeroPDARootInput from @cealis/v3-crypto", () => {
    expect(typeof zeroPDARootInput).toBe("function");
  });

  it("re-exports TAG_PDA_ROOT_V3 hex constant from @cealis/v3-crypto", () => {
    expect(typeof TAG_PDA_ROOT_V3).toBe("string");
    expect(TAG_PDA_ROOT_V3).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("TAG_PDA_ROOT_V3 has the spec value (keccak256 of 'CEALIS_V3_PDA_ROOT_V3')", () => {
    // Cross-checked against M1 src/tags.ts and S2-1 §2.3 registry.
    expect(TAG_PDA_ROOT_V3).toBe(
      "0x2e9aef6890ee90a57f6cbc9f7301799f914fe95b03dd711065ebf5b8b3fa31ec",
    );
  });

  it("TAG_COMMIT_V3 has the spec value", () => {
    expect(TAG_COMMIT_V3).toBe(
      "0x2d2217e4d967ed248e767e28fbd079ef83164a25c8cbcf94387c115336726615",
    );
  });

  it("TAG_AAD_V3 has the spec value", () => {
    expect(TAG_AAD_V3).toBe(
      "0x5f09deb22a5104e36edaa6ab19e7de91e965cd565b2b1ad45da57eaa2aae9072",
    );
  });

  it("zeroPDARootInput() produces a 540-byte preimage for the canonical zero input", () => {
    const input = zeroPDARootInput();
    const preimage = buildPDARootPreimage(input);
    // Per S2-1 §3.3.2: preimage is 540 bytes (32 TAG + 13×32 bytes32
    // + 8 pda_version + 1+1 modes + 1 auth class + 32 qtsp + 1 art_9_scoped
    // + 1 art_9_basis_id + 1 legal_effect + 1 halt_optout + 8 min_shred
    // + 32 jurisdiction + 5×1 tail booleans).
    expect(preimage.length).toBe(540);
  });

  it("computePDARoot() returns a 32-byte digest for the canonical zero input", () => {
    const input = zeroPDARootInput();
    const digest = computePDARoot(input);
    expect(digest.length).toBe(32);
  });

  it("computePDARoot() is deterministic across calls (same input → same digest)", () => {
    const input = zeroPDARootInput();
    const d1 = computePDARoot(input);
    const d2 = computePDARoot(input);
    expect(d1).toEqual(d2);
  });
});
