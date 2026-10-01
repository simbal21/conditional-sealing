import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, combineAndDecrypt } from "../../src/index.js";
import { dispatchProfile } from "../../src/combiner/index.js";
import { makeFixture } from "./combiner-testkit.js";

describe("combiner fixed sigma order", () => {
  it("rejects Lit/G3 order swaps before share admission", () => {
    const base = makeFixture();
    const evidence = [...base.sigmas.evidence];
    const first = evidence[0]!;
    evidence[0] = evidence[1]!;
    evidence[1] = first;
    const result = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.subCodes).toContain("ERR_SIGMA_ORDER_MISMATCH");
  });

  it("rejects malformed profile dispatch metadata before verification", () => {
    const base = makeFixture();
    expect(() => dispatchProfile({ commitAAD: new Uint8Array(2), sigmas: base.sigmas })).toThrow();

    // R2b-3 closure "k_conditional from commitAAD not σ-metadata"
    // (2026-05-20): σ-metadata `profileKind: "RECIPIENT_K_OF_N"` is NO
    // LONGER an authoritative override — the threshold values come from
    // the caller-supplied `conditionalRecipientsPolicy` (AAD-digest-bound)
    // or the AAD-derived `conditional_recipients_stanza_count`. The
    // σ-metadata `profileKind` label survives as a non-load-bearing hint
    // and falls through to AAD-inferred profile. The base fixture is
    // FIXED_ONLY (stanza_count=0) so the σ-metadata RECIPIENT_K_OF_N
    // label is silently ignored — the result decrypts cleanly. This is
    // the security improvement: an attacker cannot widen the threshold
    // surface via σ-metadata override anymore.
    const profileKindLabelOnly = base.sigmas.evidence.map((item) => ({
      ...item,
      metadata: { ...item.metadata, profileKind: "RECIPIENT_K_OF_N" },
    }));
    const labelResult = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence: profileKindLabelOnly },
    });
    expect(labelResult.ok).toBe(true);

    // `profileKind: "UNSUPPORTED_PROFILE"` is still rejected — that
    // assertion is in `readProfileOverride` independent of the σ-metadata
    // threshold-trust deletion (string-value validation only).
    const unsupported = base.sigmas.evidence.map((item) => ({
      ...item,
      metadata: { ...item.metadata, profileKind: "UNSUPPORTED_PROFILE" },
    }));
    const unsupportedResult = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence: unsupported },
    });
    expect(unsupportedResult.ok).toBe(false);
    if (!unsupportedResult.ok) expect(unsupportedResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET);
  });
});
