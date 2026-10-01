// ChallengeWindowLivePortImpl + RegistryDeprecationLivePortImpl tests — T3.4.
//
// Proves: (a) challenge window closed iff clock elapsed AND no late-filed
// challenge open, (b) a late-filed challenge (on-chain ChallengeOpen) keeps the
// window open even after the clock elapses, (c) registry acceptability =
// no deprecated refs, (d) both fail-closed on absent authorization / throwing
// reads / live re-read.

import { describe, expect, it, vi } from "vitest";

import { ChallengeWindowLivePortImpl } from "../../../src/reveal/live-ports/challenge-port.js";
import { RegistryDeprecationLivePortImpl } from "../../../src/reveal/live-ports/registry-port.js";
import type { ChainStateReader, AuthorizationChainState } from "../../../src/reveal/live-ports/chain-port.js";
import type { Hex32 } from "../../../src/types/reveal-artifact-bundle.js";

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}

// authorization_timestamp = 1000 (unix seconds), window = 60s → expires at
// 1060s = 1_060_000 ms.
function presentAuth(over: Partial<AuthorizationChainState> = {}): AuthorizationChainState {
  return {
    reveal_authorized_present: true,
    h_commit: hex(0x99),
    authorization_block: 100n,
    authorization_timestamp: 1000n,
    challenge_window_seconds: 60,
    ...over,
  };
}

function fakeReader(over: Partial<ChainStateReader> = {}): ChainStateReader {
  return {
    getHeadBlock: async () => 200n,
    getAuthorizationState: async () => presentAuth(),
    getCurrentShredStateRaw: async () => 0,
    isChallengeOpen: async () => false,
    getDeprecatedRefs: async () => [],
    ...over,
  };
}

describe("ChallengeWindowLivePortImpl", () => {
  it("clock not yet elapsed → window open (closed=false)", async () => {
    const reader = fakeReader();
    const port = new ChallengeWindowLivePortImpl(reader, () => 1_059_999); // 1ms before expiry

    const out = await port.read(hex(1));
    expect(out.closed).toBe(false);
    expect(out.window_expires_at).toBe(new Date(1_060_000).toISOString());
  });

  it("clock elapsed AND no challenge open → window closed (closed=true)", async () => {
    const isChallengeOpen = vi.fn(async () => false);
    const reader = fakeReader({ isChallengeOpen });
    const port = new ChallengeWindowLivePortImpl(reader, () => 1_060_001); // just past expiry

    const out = await port.read(hex(2));
    expect(out.closed).toBe(true);
    // The late-challenge live read fires only after the clock elapsed.
    expect(isChallengeOpen).toHaveBeenCalledTimes(1);
    expect(isChallengeOpen).toHaveBeenCalledWith(hex(2));
  });

  it("clock elapsed BUT a late-filed challenge is open → window stays open (closed=false)", async () => {
    // The reason this port reads LIVE: a challenge filed late in the window
    // (on-chain ChallengeOpen) keeps the window open for plain delivery even
    // though the clock elapsed.
    const reader = fakeReader({ isChallengeOpen: async () => true });
    const port = new ChallengeWindowLivePortImpl(reader, () => 1_060_001);

    const out = await port.read(hex(3));
    expect(out.closed).toBe(false);
  });

  it("does NOT read challenge state before the clock elapses (cheap path)", async () => {
    const isChallengeOpen = vi.fn(async () => false);
    const reader = fakeReader({ isChallengeOpen });
    const port = new ChallengeWindowLivePortImpl(reader, () => 1_000_000); // well before expiry

    await port.read(hex(4));
    expect(isChallengeOpen).not.toHaveBeenCalled();
  });

  it("fail-closed: absent authorization → window open (cannot prove elapsed)", async () => {
    const reader = fakeReader({ getAuthorizationState: async () => null });
    const port = new ChallengeWindowLivePortImpl(reader, () => 9_999_999_999);

    const out = await port.read(hex(5));
    expect(out.closed).toBe(false);
  });

  it("reads LIVE on each call (clock sampled fresh, no cache)", async () => {
    let now = 1_059_999;
    const reader = fakeReader({ isChallengeOpen: async () => false });
    const port = new ChallengeWindowLivePortImpl(reader, () => now);

    const before = await port.read(hex(6));
    now = 1_060_001; // time advances past expiry between reads
    const after = await port.read(hex(6));

    expect(before.closed).toBe(false);
    expect(after.closed).toBe(true);
  });

  it("fail-closed: a throwing authorization read propagates", async () => {
    const reader = fakeReader({
      getAuthorizationState: async () => {
        throw new Error("getLogs failed");
      },
    });
    const port = new ChallengeWindowLivePortImpl(reader, () => 1_060_001);
    await expect(port.read(hex(7))).rejects.toThrow("getLogs failed");
  });
});

describe("RegistryDeprecationLivePortImpl", () => {
  it("no deprecated refs → acceptable=true, empty list", async () => {
    const reader = fakeReader({ getDeprecatedRefs: async () => [] });
    const port = new RegistryDeprecationLivePortImpl(reader);

    const out = await port.read(hex(1));
    expect(out).toEqual({ acceptable: true, deprecated_refs: [] });
  });

  it("any deprecated ref → acceptable=false, refs surfaced for audit", async () => {
    const reader = fakeReader({ getDeprecatedRefs: async () => ["oracle-ref-7", "plugin-ref-2"] });
    const port = new RegistryDeprecationLivePortImpl(reader);

    const out = await port.read(hex(2));
    expect(out.acceptable).toBe(false);
    expect(out.deprecated_refs).toEqual(["oracle-ref-7", "plugin-ref-2"]);
  });

  it("reads LIVE on each call (a ref deprecated after manifest-build still blocks)", async () => {
    let refs: readonly string[] = [];
    const reader = fakeReader({
      getDeprecatedRefs: async () => {
        const r = refs;
        refs = ["dsl-ref-1"]; // ref deprecated between reads
        return r;
      },
    });
    const port = new RegistryDeprecationLivePortImpl(reader);

    const first = await port.read(hex(3));
    const second = await port.read(hex(3));

    expect(first.acceptable).toBe(true);
    expect(second.acceptable).toBe(false);
  });

  it("fail-closed: a throwing registry read propagates (never acceptable on error)", async () => {
    const reader = fakeReader({
      getDeprecatedRefs: async () => {
        throw new Error("deprecationFlag revert");
      },
    });
    const port = new RegistryDeprecationLivePortImpl(reader);
    await expect(port.read(hex(4))).rejects.toThrow("deprecationFlag revert");
  });
});
