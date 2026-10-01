import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, GateKind, ShredState, combineAndDecrypt } from "../../src/index.js";
import { BLOCK_HASH, makeFixture } from "./combiner-testkit.js";

describe("PRO-499 R3 at-commit-block discipline", () => {
  it("uses commit snapshot for KEM binding and authorization snapshot for signability", () => {
    const result = combineAndDecrypt(makeFixture());
    expect(result.ok).toBe(true);
  });

  it("rejects current/authorization substitution for commit-bound gate pubkeys", () => {
    const base = makeFixture();
    const rotated = new Map(base.registrySnapshots.commitSnapshot.gateRecipientPubkeys);
    const lit = rotated.get(`${GateKind.LitV3}:0`)!;
    rotated.set(`${GateKind.LitV3}:0`, { ...lit, kemPubkey: new Uint8Array([9, 9, 9]) });
    const result = combineAndDecrypt({
      ...base,
      registrySnapshots: {
        ...base.registrySnapshots,
        commitSnapshot: {
          ...base.registrySnapshots.commitSnapshot,
          gateRecipientPubkeys: rotated,
        },
      },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);
  });

  it("rejects missing or non-signable gate-recipient pubkeys at commit block", () => {
    const missing = makeFixture();
    const withoutLit = new Map(missing.registrySnapshots.commitSnapshot.gateRecipientPubkeys);
    withoutLit.delete(`${GateKind.LitV3}:0`);
    const missingResult = combineAndDecrypt({
      ...missing,
      registrySnapshots: {
        ...missing.registrySnapshots,
        commitSnapshot: {
          ...missing.registrySnapshots.commitSnapshot,
          gateRecipientPubkeys: withoutLit,
        },
      },
    });
    expect(missingResult.ok).toBe(false);
    if (!missingResult.ok) expect(missingResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);

    const inactive = makeFixture();
    const inactiveMap = new Map(inactive.registrySnapshots.commitSnapshot.gateRecipientPubkeys);
    const g4 = inactiveMap.get(`${GateKind.G4}:0`)!;
    inactiveMap.set(`${GateKind.G4}:0`, { ...g4, effectiveBlock: 11n });
    const inactiveResult = combineAndDecrypt({
      ...inactive,
      registrySnapshots: {
        ...inactive.registrySnapshots,
        commitSnapshot: {
          ...inactive.registrySnapshots.commitSnapshot,
          gateRecipientPubkeys: inactiveMap,
        },
      },
    });
    expect(inactiveResult.ok).toBe(false);
    if (!inactiveResult.ok) expect(inactiveResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);
  });

  it("rejects snapshot block/hash substitution and G4 refusal at authorization block", () => {
    const wrongCommitBlock = makeFixture();
    const commitBlockResult = combineAndDecrypt({
      ...wrongCommitBlock,
      registrySnapshots: {
        ...wrongCommitBlock.registrySnapshots,
        commitSnapshot: {
          ...wrongCommitBlock.registrySnapshots.commitSnapshot,
          snapshot: { ...wrongCommitBlock.registrySnapshots.commitSnapshot.snapshot, blockNumber: 11n },
        },
      },
    });
    expect(commitBlockResult.ok).toBe(false);
    if (!commitBlockResult.ok) expect(commitBlockResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);

    const wrongAuth = makeFixture();
    const authBlockResult = combineAndDecrypt({
      ...wrongAuth,
      registrySnapshots: {
        ...wrongAuth.registrySnapshots,
        authorizationSnapshot: {
          ...wrongAuth.registrySnapshots.authorizationSnapshot,
          snapshot: { ...wrongAuth.registrySnapshots.authorizationSnapshot.snapshot, blockNumber: 21n },
        },
      },
    });
    expect(authBlockResult.ok).toBe(false);
    if (!authBlockResult.ok) expect(authBlockResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);

    const wrongHash = makeFixture();
    const hashResult = combineAndDecrypt({ ...wrongHash, blockHash: BLOCK_HASH.replace(/3/g, "4") as typeof BLOCK_HASH });
    expect(hashResult.ok).toBe(false);
    if (!hashResult.ok) expect(hashResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);

    const refused = makeFixture();
    const refusalResult = combineAndDecrypt({
      ...refused,
      registrySnapshots: {
        ...refused.registrySnapshots,
        authorizationSnapshot: {
          ...refused.registrySnapshots.authorizationSnapshot,
          refusalState: { refused: true, reasonCode: 0x02, encrypted: false },
        },
      },
    });
    expect(refusalResult.ok).toBe(false);
    if (!refusalResult.ok) expect(refusalResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_REFUSED);
  });

  it("blocks non-signable shred states before share admission", () => {
    const result = combineAndDecrypt(makeFixture({ shredState: ShredState.Finalized }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHRED_STATE_BLOCKED);
  });
});
