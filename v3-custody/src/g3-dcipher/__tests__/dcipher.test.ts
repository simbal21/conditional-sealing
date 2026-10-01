import { describe, expect, it } from "vitest";

import {
  fetchDcipherCommitteeAtAuthorization,
  loadDcipherSdk,
  verifyDcipherKemContinuity,
  verifyDcipherSigma,
} from "../index.js";

describe("g3-dcipher adapter", () => {
  it("is build-excluded when the Randamu SDK is not present", () => {
    const loaded = loadDcipherSdk();
    expect(loaded.included).toBe(false);
    expect(loaded.status.status).toBe("deferred");
  });

  it("surfaces registry-unavailable without inventing a committee", async () => {
    await expect(
      fetchDcipherCommitteeAtAuthorization({ authorizationBlock: 100n }),
    ).rejects.toMatchObject({
      code: "CUSTODY_ERR_DCIPHER_REGISTRY_UNAVAILABLE",
    });
  });

  it("rejects absent KEM continuity even if a signature path later verifies", () => {
    const result = verifyDcipherKemContinuity({
      authorizationBlock: 100n,
      commitBinding: {
        committeeId: "commit-committee",
        committeeEpoch: 1n,
        kemPubkeyDigest: new Uint8Array(32),
        registryEntryId: "commit-entry",
      },
      authorizationCommittee: {
        committeeId: "authorization-committee",
        committeeEpoch: 2n,
        verificationPubkey: new Uint8Array(48),
        membershipDigest: hex32(1),
        effectiveBlock: 1n,
        tombstoneBlock: 0n,
        registryEntryId: "authorization-entry",
      },
    });
    expect(result).toEqual({
      ok: false,
      code: "CUSTODY_ERR_GATE_PUBKEY_MISMATCH",
      detail:
        "dcipher committee signing key is not linked to the commit-bound KEM key",
    });
  });

  it("maps the M1 dcipher verifier stub to SDK-not-pinned", () => {
    expect(
      verifyDcipherSigma({
        authorizationId: new Uint8Array(32),
        hCommit: new Uint8Array(32),
        blockHash: new Uint8Array(32),
        signature: new Uint8Array(96),
        committeePubkey: new Uint8Array(48),
      }),
    ).toEqual({
      ok: false,
      code: "CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED",
      detail: "ERR_SIGMA_G3_DCIPHER_VERIFY_STUB",
    });
  });
});

function hex32(seed: number): `0x${string}` {
  return `0x${seed.toString(16).padStart(2, "0").repeat(32)}`;
}
