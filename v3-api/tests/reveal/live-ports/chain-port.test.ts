// ChainConfirmationLivePortImpl + ViemChainStateReader tests — T3.4.
//
// Proves: (a) confirmation depth = head − authorization_block, (b) fail-closed
// when no RevealAuthorized is present, (c) the port re-reads head live (no
// cache), (d) the ViemChainStateReader decodes RevealAuthorized logs + resolves
// shred/deprecation via the injected registry reader, with NO hardcoded address.

import { describe, expect, it, vi } from "vitest";

import {
  ChainConfirmationLivePortImpl,
  ViemChainStateReader,
  type ChainStateReader,
  type AuthorizationChainState,
  type ViemPublicClientLike,
  type RegistryDeprecationReader,
} from "../../../src/reveal/live-ports/chain-port.js";
import type { Hex32 } from "../../../src/types/reveal-artifact-bundle.js";

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}

function presentAuth(over: Partial<AuthorizationChainState> = {}): AuthorizationChainState {
  return {
    reveal_authorized_present: true,
    h_commit: hex(0x99),
    authorization_block: 100n,
    authorization_timestamp: 1_778_000_000n,
    challenge_window_seconds: 60,
    ...over,
  };
}

function fakeReader(over: Partial<ChainStateReader> = {}): ChainStateReader {
  return {
    getHeadBlock: async () => 132n,
    getAuthorizationState: async () => presentAuth(),
    getCurrentShredStateRaw: async () => 0,
    isChallengeOpen: async () => false,
    getDeprecatedRefs: async () => [],
    ...over,
  };
}

describe("ChainConfirmationLivePortImpl", () => {
  it("confirmations = head − authorization_block", async () => {
    const reader = fakeReader({ getHeadBlock: async () => 132n, getAuthorizationState: async () => presentAuth({ authorization_block: 100n }) });
    const port = new ChainConfirmationLivePortImpl(reader);

    const out = await port.read(hex(1));

    expect(out).toEqual({
      reveal_authorized_present: true,
      confirmations: 32,
      authorization_block: 100,
    });
  });

  it("fail-closed: no RevealAuthorized present → not present, 0 confirmations", async () => {
    const reader = fakeReader({ getAuthorizationState: async () => null });
    const port = new ChainConfirmationLivePortImpl(reader);

    const out = await port.read(hex(2));

    expect(out).toEqual({
      reveal_authorized_present: false,
      confirmations: 0,
      authorization_block: 0,
    });
  });

  it("reorg below the authorization block clamps confirmations to 0 (block)", async () => {
    // head moved below the authorization block — confirmations must not go
    // negative; clamp to 0 so the coordinator blocks.
    const reader = fakeReader({
      getHeadBlock: async () => 90n,
      getAuthorizationState: async () => presentAuth({ authorization_block: 100n }),
    });
    const port = new ChainConfirmationLivePortImpl(reader);

    const out = await port.read(hex(3));
    expect(out.confirmations).toBe(0);
  });

  it("reads head LIVE on each call (no cache)", async () => {
    let head = 101n;
    const reader = fakeReader({
      getHeadBlock: async () => {
        const v = head;
        head += 1n;
        return v;
      },
      getAuthorizationState: async () => presentAuth({ authorization_block: 100n }),
    });
    const spy = vi.spyOn(reader, "getHeadBlock");
    const port = new ChainConfirmationLivePortImpl(reader);

    const a = await port.read(hex(4));
    const b = await port.read(hex(4));

    expect(a.confirmations).toBe(1);
    expect(b.confirmations).toBe(2);
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("fail-closed: a throwing head read propagates", async () => {
    const reader = fakeReader({
      getHeadBlock: async () => {
        throw new Error("getBlockNumber failed");
      },
    });
    const port = new ChainConfirmationLivePortImpl(reader);
    await expect(port.read(hex(5))).rejects.toThrow("getBlockNumber failed");
  });
});

// ─── ViemChainStateReader (production boundary) ───

const REVEAL_AUTHORIZED_EVENT = {
  type: "event",
  name: "RevealAuthorized",
  inputs: [
    { name: "authorizationId", type: "bytes32", indexed: true },
    { name: "hCommit", type: "bytes32", indexed: true },
    { name: "pdaRoot", type: "bytes32", indexed: true },
    { name: "authorizationBlock", type: "uint64", indexed: false },
    { name: "authorizationTimestamp", type: "uint64", indexed: false },
    { name: "challengeWindow", type: "uint32", indexed: false },
    { name: "conditionRef", type: "bytes32", indexed: false },
  ],
};

function fakeRegistry(over: Partial<RegistryDeprecationReader> = {}): RegistryDeprecationReader {
  return {
    getCurrentShredState: async () => 0,
    getDeprecatedRefs: async () => [],
    ...over,
  };
}

describe("ViemChainStateReader", () => {
  it("getHeadBlock delegates to publicClient.getBlockNumber", async () => {
    const publicClient: ViemPublicClientLike = {
      getBlockNumber: async () => 4242n,
      getBlock: async () => ({ timestamp: 0n }),
      getLogs: async () => [],
      readContract: async () => 0,
    };
    const reader = new ViemChainStateReader({
      publicClient,
      conditionEngineAddress: "0x00000000000000000000000000000000000000ce",
      revealAuthorizedEvent: REVEAL_AUTHORIZED_EVENT,
      registry: fakeRegistry(),
    });
    expect(await reader.getHeadBlock()).toBe(4242n);
  });

  it("getAuthorizationState decodes the RevealAuthorized log (block, ts, window, h_commit)", async () => {
    const publicClient: ViemPublicClientLike = {
      getBlockNumber: async () => 200n,
      getBlock: async () => ({ timestamp: 0n }),
      getLogs: async (args) => {
        // The scan keys on the indexed authorizationId topic.
        expect(args["address"]).toBe("0x00000000000000000000000000000000000000ce");
        expect((args["args"] as { authorizationId: Hex32 }).authorizationId).toBe(hex(0x31));
        return [
          {
            blockNumber: 200n,
            args: {
              hCommit: hex(0x32),
              authorizationBlock: 200n,
              authorizationTimestamp: 1_778_489_600n,
              challengeWindow: 60,
            },
          },
        ];
      },
      readContract: async () => 0,
    };
    const reader = new ViemChainStateReader({
      publicClient,
      conditionEngineAddress: "0x00000000000000000000000000000000000000ce",
      revealAuthorizedEvent: REVEAL_AUTHORIZED_EVENT,
      registry: fakeRegistry(),
    });

    const out = await reader.getAuthorizationState(hex(0x31));
    expect(out).toEqual({
      reveal_authorized_present: true,
      h_commit: hex(0x32),
      authorization_block: 200n,
      authorization_timestamp: 1_778_489_600n,
      challenge_window_seconds: 60,
    });
  });

  it("getAuthorizationState returns null when no log matches (fail-closed source)", async () => {
    const publicClient: ViemPublicClientLike = {
      getBlockNumber: async () => 200n,
      getBlock: async () => ({ timestamp: 0n }),
      getLogs: async () => [],
      readContract: async () => 0,
    };
    const reader = new ViemChainStateReader({
      publicClient,
      conditionEngineAddress: "0x00000000000000000000000000000000000000ce",
      revealAuthorizedEvent: REVEAL_AUTHORIZED_EVENT,
      registry: fakeRegistry(),
    });
    expect(await reader.getAuthorizationState(hex(0x31))).toBeNull();
  });

  it("getAuthorizationState reads the block timestamp live when the event omits it", async () => {
    const getBlock = vi.fn(async () => ({ timestamp: 1_778_111_111n }));
    const publicClient: ViemPublicClientLike = {
      getBlockNumber: async () => 200n,
      getBlock,
      getLogs: async () => [
        { blockNumber: 150n, args: { hCommit: hex(0x32), authorizationBlock: 150n, authorizationTimestamp: 0n, challengeWindow: 30 } },
      ],
      readContract: async () => 0,
    };
    const reader = new ViemChainStateReader({
      publicClient,
      conditionEngineAddress: "0x00000000000000000000000000000000000000ce",
      revealAuthorizedEvent: REVEAL_AUTHORIZED_EVENT,
      registry: fakeRegistry(),
    });

    const out = await reader.getAuthorizationState(hex(0x31));
    expect(out?.authorization_timestamp).toBe(1_778_111_111n);
    expect(getBlock).toHaveBeenCalledWith({ blockNumber: 150n });
  });

  it("isChallengeOpen resolves the bound h_commit then reads ChallengeOpen (5)", async () => {
    const getCurrentShredState = vi.fn(async (h: Hex32) => {
      expect(h).toBe(hex(0x32)); // resolved from the authorization's h_commit topic
      return 5; // ChallengeOpen
    });
    const publicClient: ViemPublicClientLike = {
      getBlockNumber: async () => 200n,
      getBlock: async () => ({ timestamp: 0n }),
      getLogs: async () => [
        { blockNumber: 200n, args: { hCommit: hex(0x32), authorizationBlock: 200n, authorizationTimestamp: 1n, challengeWindow: 60 } },
      ],
      readContract: async () => 0,
    };
    const reader = new ViemChainStateReader({
      publicClient,
      conditionEngineAddress: "0x00000000000000000000000000000000000000ce",
      revealAuthorizedEvent: REVEAL_AUTHORIZED_EVENT,
      registry: fakeRegistry({ getCurrentShredState }),
    });

    expect(await reader.isChallengeOpen(hex(0x31))).toBe(true);
    expect(getCurrentShredState).toHaveBeenCalledTimes(1);
  });

  it("isChallengeOpen returns false when the authorization is absent", async () => {
    const publicClient: ViemPublicClientLike = {
      getBlockNumber: async () => 200n,
      getBlock: async () => ({ timestamp: 0n }),
      getLogs: async () => [],
      readContract: async () => 0,
    };
    const reader = new ViemChainStateReader({
      publicClient,
      conditionEngineAddress: "0x00000000000000000000000000000000000000ce",
      revealAuthorizedEvent: REVEAL_AUTHORIZED_EVENT,
      registry: fakeRegistry(),
    });
    expect(await reader.isChallengeOpen(hex(0x31))).toBe(false);
  });

  it("getCurrentShredStateRaw + getDeprecatedRefs delegate to the injected registry", async () => {
    const reader = new ViemChainStateReader({
      publicClient: {
        getBlockNumber: async () => 1n,
        getBlock: async () => ({ timestamp: 0n }),
        getLogs: async () => [],
        readContract: async () => 0,
      },
      conditionEngineAddress: "0x00000000000000000000000000000000000000ce",
      revealAuthorizedEvent: REVEAL_AUTHORIZED_EVENT,
      registry: fakeRegistry({
        getCurrentShredState: async () => 3,
        getDeprecatedRefs: async () => ["plugin-ref-1"],
      }),
    });

    expect(await reader.getCurrentShredStateRaw(hex(0x32))).toBe(3);
    expect(await reader.getDeprecatedRefs(hex(0x31))).toEqual(["plugin-ref-1"]);
  });
});
