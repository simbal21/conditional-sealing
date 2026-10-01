// Composition test — T3.4: the 5 real LiveStateReaderPorts plug into the
// EXISTING ConcreteLiveStateReader + clearGatesAt without modification.
//
// This is the integration seam the task names: "Compose via existing
// ConcreteLiveStateReader." It proves the 5 impls satisfy the frozen port
// interfaces AND that the reader stamps `read_at` + clearGatesAt mints a
// well-formed phase-branded clearance from real-port evidence — i.e. the ports
// drop into the coordinator's live-state path with no shim.

import { describe, expect, it } from "vitest";

import {
  ConcreteLiveStateReader,
  clearGatesAt,
  type LiveStateReaderPorts,
} from "../../../src/reveal/reveal-coordinator-impl.js";
import {
  ChainConfirmationLivePortImpl,
  ShredStateLivePortImpl,
  ChallengeWindowLivePortImpl,
  RegistryDeprecationLivePortImpl,
  Art18FreezeLivePortImpl,
  type ChainStateReader,
  type AuthorizationChainState,
} from "../../../src/reveal/live-ports/index.js";
import type { Art18FreezeStore } from "../../../src/reveal/live-ports/art18-port.js";
import type { Hex32 } from "../../../src/types/reveal-artifact-bundle.js";

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}

const SUBJECT = {
  authorizationId: hex(0x31),
  h_commit: hex(0x32),
  subjectCommitment: hex(0x33),
};

// authorization_timestamp 1000s, window 60s → expires 1_060_000 ms.
function chainReader(over: Partial<ChainStateReader> = {}): ChainStateReader {
  const auth: AuthorizationChainState = {
    reveal_authorized_present: true,
    h_commit: SUBJECT.h_commit,
    authorization_block: 100n,
    authorization_timestamp: 1000n,
    challenge_window_seconds: 60,
  };
  return {
    getHeadBlock: async () => 140n, // 40 confirmations
    getAuthorizationState: async () => auth,
    getCurrentShredStateRaw: async () => 0, // None
    isChallengeOpen: async () => false,
    getDeprecatedRefs: async () => [],
    ...over,
  };
}

function freezeStore(frozen: boolean): Art18FreezeStore {
  return {
    getActiveFreeze: async () =>
      frozen ? { subject_commitment: SUBJECT.subjectCommitment, freeze_expires_at: new Date(2_000_000).toISOString() } : null,
  };
}

function buildPorts(
  chain: ChainStateReader,
  store: Art18FreezeStore,
  nowMs: number,
): LiveStateReaderPorts {
  return {
    shred: new ShredStateLivePortImpl(chain),
    art18: new Art18FreezeLivePortImpl(store, () => nowMs),
    chain: new ChainConfirmationLivePortImpl(chain),
    challenge: new ChallengeWindowLivePortImpl(chain, () => nowMs),
    registry: new RegistryDeprecationLivePortImpl(chain),
  };
}

describe("5 real ports compose via ConcreteLiveStateReader", () => {
  it("a fully-cleared (deliverable) state yields evidence that passes every axis", async () => {
    const nowMs = 1_060_001; // just past challenge expiry → window closed
    const reader = new ConcreteLiveStateReader(buildPorts(chainReader(), freezeStore(false), nowMs));

    const clearance = await clearGatesAt("pre-delivery", reader, SUBJECT);

    expect(clearance.phase).toBe("pre-delivery");
    expect(typeof clearance.cleared_at).toBe("string");

    const ev = clearance.evidence;
    // Each axis carries a real read_at (the reader stamps it).
    expect(typeof ev.shred.read_at).toBe("string");
    expect(ev.shred).toMatchObject({ state: "none", post_challenge_reveal_in_progress: false });
    expect(ev.art18).toMatchObject({ frozen: false });
    expect(ev.chain).toMatchObject({ reveal_authorized_present: true, confirmations: 40 });
    expect(ev.challenge).toMatchObject({ closed: true });
    expect(ev.registry).toMatchObject({ acceptable: true, deprecated_refs: [] });
  });

  it("a finalized shred surfaces through the reader's evidence (coordinator would block)", async () => {
    const nowMs = 1_060_001;
    const reader = new ConcreteLiveStateReader(
      buildPorts(chainReader({ getCurrentShredStateRaw: async () => 3 /* Finalized */ }), freezeStore(false), nowMs),
    );

    const clearance = await clearGatesAt("pre-delivery", reader, SUBJECT);
    expect(clearance.evidence.shred.state).toBe("finalized");
  });

  it("an active Art.18 freeze surfaces as frozen evidence (coordinator would block)", async () => {
    const nowMs = 1_060_001;
    const reader = new ConcreteLiveStateReader(buildPorts(chainReader(), freezeStore(true), nowMs));

    const clearance = await clearGatesAt("pre-delivery", reader, SUBJECT);
    expect(clearance.evidence.art18.frozen).toBe(true);
  });

  it("a still-open challenge window surfaces closed=false (coordinator would block)", async () => {
    const nowMs = 1_000_000; // before expiry
    const reader = new ConcreteLiveStateReader(buildPorts(chainReader(), freezeStore(false), nowMs));

    const clearance = await clearGatesAt("pre-delivery", reader, SUBJECT);
    expect(clearance.evidence.challenge.closed).toBe(false);
  });

  it("a deprecated registry ref surfaces acceptable=false (coordinator would block)", async () => {
    const nowMs = 1_060_001;
    const reader = new ConcreteLiveStateReader(
      buildPorts(chainReader({ getDeprecatedRefs: async () => ["oracle-ref-9"] }), freezeStore(false), nowMs),
    );

    const clearance = await clearGatesAt("pre-delivery", reader, SUBJECT);
    expect(clearance.evidence.registry.acceptable).toBe(false);
    expect(clearance.evidence.registry.deprecated_refs).toEqual(["oracle-ref-9"]);
  });

  it("re-clearing reads fresh state (no snapshot across clearGatesAt calls)", async () => {
    let shredRaw = 0; // None first
    const reader = new ConcreteLiveStateReader(
      buildPorts(
        chainReader({
          getCurrentShredStateRaw: async () => {
            const v = shredRaw;
            shredRaw = 3; // Finalized on the second read
            return v;
          },
        }),
        freezeStore(false),
        1_060_001,
      ),
    );

    const first = await clearGatesAt("pre-delivery", reader, SUBJECT);
    const second = await clearGatesAt("pre-delivery", reader, SUBJECT);

    expect(first.evidence.shred.state).toBe("none");
    expect(second.evidence.shred.state).toBe("finalized");
  });
});
