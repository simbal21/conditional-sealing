import { describe, expect, it } from "vitest";

import { verifyDcipherKemContinuity } from "../../src/g3-dcipher/index.js";

describe("integration: g3 dcipher KEM continuity", () => {
  it("rejects valid-signature-shaped flow when continuity proof is absent", () => {
    const result = verifyDcipherKemContinuity({
      authorizationBlock: 50n,
      commitBinding: {
        committeeId: "commit",
        committeeEpoch: 1n,
        kemPubkeyDigest: new Uint8Array(32),
        registryEntryId: "commit-entry",
      },
      authorizationCommittee: {
        committeeId: "auth",
        committeeEpoch: 2n,
        verificationPubkey: new Uint8Array(48),
        membershipDigest: `0x${"11".repeat(32)}`,
        effectiveBlock: 1n,
        tombstoneBlock: 0n,
        registryEntryId: "auth-entry",
      },
    });
    expect(result).toMatchObject({
      ok: false,
      code: "CUSTODY_ERR_GATE_PUBKEY_MISMATCH",
    });
  });
});
