// ShredStateLivePortImpl tests — T3.4.
//
// Proves: (a) every M2 ShredState enum value maps to the correct coordinator
// (state, guardrail) pair, (b) the port reads LIVE from the injected chain
// reader at call time, (c) fail-closed on out-of-range + on a throwing read.

import { describe, expect, it, vi } from "vitest";

import { ShredStateLivePortImpl, mapM2ShredState } from "../../../src/reveal/live-ports/shred-port.js";
import type { ChainStateReader, AuthorizationChainState } from "../../../src/reveal/live-ports/chain-port.js";
import type { Hex32 } from "../../../src/types/reveal-artifact-bundle.js";

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}

/** Minimal fake chain reader whose shred state is settable per call. */
function fakeReader(shredRaw: number | (() => never)): ChainStateReader {
  return {
    getHeadBlock: async () => 0n,
    getAuthorizationState: async (): Promise<AuthorizationChainState | null> => null,
    getCurrentShredStateRaw: async () => {
      if (typeof shredRaw === "function") return shredRaw();
      return shredRaw;
    },
    isChallengeOpen: async () => false,
    getDeprecatedRefs: async () => [],
  };
}

describe("mapM2ShredState — M2 7-value enum → coordinator lifecycle + guardrail", () => {
  it("None (0) → none, guardrail=false", () => {
    expect(mapM2ShredState(0)).toEqual({ state: "none", post_challenge_reveal_in_progress: false });
  });

  it("Requested (1) → requested, guardrail=false", () => {
    expect(mapM2ShredState(1)).toEqual({ state: "requested", post_challenge_reveal_in_progress: false });
  });

  it("Authorized (2) → finalized (conservative block), guardrail=false", () => {
    expect(mapM2ShredState(2)).toEqual({ state: "finalized", post_challenge_reveal_in_progress: false });
  });

  it("Finalized (3) → finalized, guardrail=false", () => {
    expect(mapM2ShredState(3)).toEqual({ state: "finalized", post_challenge_reveal_in_progress: false });
  });

  it("Blocked (4) → finalized (admin halt), guardrail=false", () => {
    expect(mapM2ShredState(4)).toEqual({ state: "finalized", post_challenge_reveal_in_progress: false });
  });

  it("ChallengeOpen (5) → requested, guardrail=TRUE (post-challenge reveal in progress)", () => {
    // This is the ONLY combination that keeps the reveal alive while a shred
    // request exists — the mandatory `NOT post_challenge_reveal_in_progress`
    // guardrail is ACTIVE, so the reveal proceeds.
    expect(mapM2ShredState(5)).toEqual({ state: "requested", post_challenge_reveal_in_progress: true });
  });

  it("Shredded (6) → finalized (data gone), guardrail=false", () => {
    expect(mapM2ShredState(6)).toEqual({ state: "finalized", post_challenge_reveal_in_progress: false });
  });

  it("out-of-range value throws (fail-closed, never silently 'none')", () => {
    expect(() => mapM2ShredState(7)).toThrow(/out-of-range/);
    expect(() => mapM2ShredState(-1)).toThrow(/out-of-range/);
  });
});

describe("ShredStateLivePortImpl — live read", () => {
  it("reads the live shred state from the chain reader at call time", async () => {
    const reader = fakeReader(1);
    const spy = vi.spyOn(reader, "getCurrentShredStateRaw");
    const port = new ShredStateLivePortImpl(reader);

    const out = await port.read(hex(0xaa));

    expect(out).toEqual({ state: "requested", post_challenge_reveal_in_progress: false });
    // LIVE: the read hit the reader exactly once, with the h_commit.
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(hex(0xaa));
  });

  it("re-reads live on each call (no cache)", async () => {
    let next = 0;
    const reader: ChainStateReader = {
      ...fakeReader(0),
      getCurrentShredStateRaw: async () => {
        const v = next;
        next = 3; // state changes after first read
        return v;
      },
    };
    const port = new ShredStateLivePortImpl(reader);

    const first = await port.read(hex(1));
    const second = await port.read(hex(1));

    // First read = None (allow); second read = Finalized (block). No snapshot.
    expect(first.state).toBe("none");
    expect(second.state).toBe("finalized");
  });

  it("fail-closed: a throwing chain read propagates (never swallowed)", async () => {
    const reader = fakeReader(() => {
      throw new Error("RPC down");
    });
    const port = new ShredStateLivePortImpl(reader);

    await expect(port.read(hex(2))).rejects.toThrow("RPC down");
  });
});
