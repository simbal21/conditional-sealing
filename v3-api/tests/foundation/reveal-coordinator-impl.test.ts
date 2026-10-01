// Foundation tests for the R2b RevealCoordinatorImpl.
//
// These tests are the D5 adversarial-construction gate from the R2b worker-1
// brief: prove (at compile time AND at runtime) that snapshot-once is
// uninhabitable against the frozen RevealCoordinator seam.
//
// Test discipline (per internal testing rules "Vitest test discovery"):
//   - This file lives under `tests/` (vitest.config.ts include glob).
//   - `globals: false` is set in vitest.config.ts, so we import describe/it/expect.

import { describe, expect, it, vi } from "vitest";

// Stub processRevealAuthorizedEvent for v0.2 tests that exercise the
// coordinator's enqueue path without engaging the real combiner. The
// hoisted stub returns a configurable EventDrivenRevealResult; tests
// install their own per-test override via __setProcessRevealStub.
//
// Tests in earlier describe blocks that throw in buildCombinerInput before
// reaching the combiner are unaffected — the stub is never invoked there.
vi.mock("../../src/combiner-orchestrator/index.js", async (importOriginal) => {
  const original = (await importOriginal()) as Record<string, unknown>;
  // ProcessRevealFn is the real signature of processRevealAuthorizedEvent; we
  // erase the precise generics here to avoid an `import()` type annotation
  // (eslint @typescript-eslint/consistent-type-imports) and use the statically-
  // imported `processRevealAuthorizedEvent` type below for test-time stubs.
  type ProcessRevealFn = (input: unknown, deps: unknown) => Promise<unknown>;
  let currentStub: ProcessRevealFn = original.processRevealAuthorizedEvent as ProcessRevealFn;
  (globalThis as unknown as { __setProcessRevealStub?: (s: ProcessRevealFn) => void })
    .__setProcessRevealStub = (s) => {
    currentStub = s;
  };
  return {
    ...original,
    processRevealAuthorizedEvent: ((input: unknown, deps: unknown) => currentStub(input, deps)) as ProcessRevealFn,
  };
});

import {
  type Art18FreezeLivePort,
  type ChainConfirmationLivePort,
  type ChallengeWindowLivePort,
  ConcreteLiveStateReader,
  type LiveStateReaderPorts,
  type RegistryDeprecationLivePort,
  RevealCoordinatorImpl,
  type ShredStateLivePort,
  clearGatesAt,
} from "../../src/reveal/reveal-coordinator-impl.js";
import type {
  EventDrivenRevealInput,
  EventDrivenRevealResult,
} from "../../src/combiner-orchestrator/index.js";
import type {
  GateClearance,
  RevealCoordinatorInput,
  RevealCoordinatorPorts,
  RevealDeliveryQueue,
} from "../../src/reveal/reveal-coordinator.js";
import { RevealCoordinatorError } from "../../src/reveal/reveal-coordinator.js";
import type { Hex32, RevealArtifactBundle } from "../../src/types/reveal-artifact-bundle.js";
import { makeRevealCombinerDoubles } from "../_helpers/reveal-combiner-testkit.js";

// F-API-1: inert combiner doubles for the gate-failure / vi.mock-stubbed paths
// in this file. None of these coordinators reaches the REAL combine+decrypt join
// (the gate blocks first, or processRevealAuthorizedEvent is mocked at the top),
// so the doubles are supplied only to satisfy the deps + input types — they are
// never actually invoked.
const INERT_DOUBLES = makeRevealCombinerDoubles({ legal_name: "Alice" });

const H32_A = ("0x" + "a".repeat(64)) as Hex32;
const H32_B = ("0x" + "b".repeat(64)) as Hex32;
const H32_C = ("0x" + "c".repeat(64)) as Hex32;

const SUBJECT = {
  authorizationId: H32_A,
  h_commit: H32_B,
  subjectCommitment: H32_C,
};

const COORDINATOR_INPUT: RevealCoordinatorInput = {
  authorizationId: H32_A,
  h_commit: H32_B,
  subjectCommitment: H32_C,
  partner_id: "test-partner",
  pda_id: "test-pda",
};

// ─── Fixtures: stub per-axis live ports ────────────────────────────────────

function makePorts(overrides?: {
  shred?: Awaited<ReturnType<ShredStateLivePort["read"]>>;
  art18?: Awaited<ReturnType<Art18FreezeLivePort["read"]>>;
  chain?: Awaited<ReturnType<ChainConfirmationLivePort["read"]>>;
  challenge?: Awaited<ReturnType<ChallengeWindowLivePort["read"]>>;
  registry?: Awaited<ReturnType<RegistryDeprecationLivePort["read"]>>;
}): LiveStateReaderPorts {
  const defaultShred: Awaited<ReturnType<ShredStateLivePort["read"]>> = {
    state: "none",
    post_challenge_reveal_in_progress: false,
  };
  const defaultArt18: Awaited<ReturnType<Art18FreezeLivePort["read"]>> = { frozen: false };
  const defaultChain: Awaited<ReturnType<ChainConfirmationLivePort["read"]>> = {
    reveal_authorized_present: true,
    confirmations: 12,
    authorization_block: 1_000_000,
  };
  const defaultChallenge: Awaited<ReturnType<ChallengeWindowLivePort["read"]>> = {
    closed: true,
    window_expires_at: "2026-01-01T00:00:00.000Z",
  };
  const defaultRegistry: Awaited<ReturnType<RegistryDeprecationLivePort["read"]>> = {
    acceptable: true,
    deprecated_refs: [],
  };
  return {
    shred: { read: vi.fn(async () => overrides?.shred ?? defaultShred) },
    art18: { read: vi.fn(async () => overrides?.art18 ?? defaultArt18) },
    chain: { read: vi.fn(async () => overrides?.chain ?? defaultChain) },
    challenge: { read: vi.fn(async () => overrides?.challenge ?? defaultChallenge) },
    registry: { read: vi.fn(async () => overrides?.registry ?? defaultRegistry) },
  };
}

function makeQueue(): { queue: RevealDeliveryQueue; enqueued: { job_id: string }[]; deadLettered: { jobId: string; reason: string }[] } {
  const enqueued: { job_id: string }[] = [];
  const deadLettered: { jobId: string; reason: string }[] = [];
  const queue: RevealDeliveryQueue = {
    enqueue: async (job) => {
      enqueued.push({ job_id: job.job_id });
    },
    deadLetter: async (jobId, reason) => {
      deadLettered.push({ jobId, reason });
    },
  };
  return { queue, enqueued, deadLettered };
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("ConcreteLiveStateReader", () => {
  it("readShredState calls the live port and stamps read_at fresh", async () => {
    const ports = makePorts();
    const reader = new ConcreteLiveStateReader(ports, () => "2026-05-19T12:00:00.000Z");
    const live = await reader.readShredState(H32_B);
    expect(live.state).toBe("none");
    expect(live.read_at).toBe("2026-05-19T12:00:00.000Z");
    expect(ports.shred.read).toHaveBeenCalledWith(H32_B);
    expect(ports.shred.read).toHaveBeenCalledTimes(1);
  });

  it("readArt18Freeze passes through freeze_expires_at when present", async () => {
    const ports = makePorts({ art18: { frozen: true, freeze_expires_at: "2026-08-01T00:00:00.000Z" } });
    const reader = new ConcreteLiveStateReader(ports, () => "2026-05-19T12:00:00.000Z");
    const live = await reader.readArt18Freeze(H32_C);
    expect(live.frozen).toBe(true);
    expect(live.freeze_expires_at).toBe("2026-08-01T00:00:00.000Z");
  });

  it("EACH read method is a separate live port call (no caching)", async () => {
    const ports = makePorts();
    const reader = new ConcreteLiveStateReader(ports);
    await reader.readShredState(H32_B);
    await reader.readShredState(H32_B);
    expect(ports.shred.read).toHaveBeenCalledTimes(2);
  });
});

describe("clearGatesAt — the SOLE GateClearance constructor", () => {
  it("awaits ALL 5 live readers before minting clearance", async () => {
    const ports = makePorts();
    const reader = new ConcreteLiveStateReader(ports);
    const clearance = await clearGatesAt("pre-delivery", reader, SUBJECT);
    expect(clearance.phase).toBe("pre-delivery");
    expect(clearance.evidence.shred.state).toBe("none");
    expect(clearance.evidence.art18.frozen).toBe(false);
    expect(clearance.evidence.chain.reveal_authorized_present).toBe(true);
    expect(clearance.evidence.challenge.closed).toBe(true);
    expect(clearance.evidence.registry.acceptable).toBe(true);
    // All 5 ports were hit.
    expect(ports.shred.read).toHaveBeenCalledTimes(1);
    expect(ports.art18.read).toHaveBeenCalledTimes(1);
    expect(ports.chain.read).toHaveBeenCalledTimes(1);
    expect(ports.challenge.read).toHaveBeenCalledTimes(1);
    expect(ports.registry.read).toHaveBeenCalledTimes(1);
  });

  it("brands distinct phases as distinct (entry vs pre-delivery)", async () => {
    const ports = makePorts();
    const reader = new ConcreteLiveStateReader(ports);
    const entry = await clearGatesAt("entry", reader, SUBJECT);
    const preDelivery = await clearGatesAt("pre-delivery", reader, SUBJECT);
    expect(entry.phase).toBe("entry");
    expect(preDelivery.phase).toBe("pre-delivery");
    // Each call re-reads all 5 ports — 5 + 5 = 10 reads across both phases.
    expect(ports.shred.read).toHaveBeenCalledTimes(2);
  });
});

describe("RevealCoordinatorImpl — defense-in-depth on clearance evidence", () => {
  // Build a coordinator whose buildCombinerInput synthesizes a no-op input
  // and combinerDeps uses an InMemoryRevealArtifactRepository — that
  // suffices to exercise the gate logic. The mission brief says C3a is
  // tested at the gate level here; the combiner-orchestrator's own crypto
  // logic is covered by its own existing tests.
  function makeCoordinator(): RevealCoordinatorImpl {
    return new RevealCoordinatorImpl(
      {
        // Minimal RevealArtifactRepository stub — every method resolves; for
        // the gate-failure tests below the combiner is never reached.
        repository: {
          upsertStatus: async () => {},
          getStatus: async () => undefined,
          putManifest: async () => {},
          getManifest: async () => undefined,
          putBundle: async () => {},
          getBundle: async () => undefined,
          listBundles: async () => [],
        },
        sigmaGatherer: INERT_DOUBLES.sigmaGatherer,
        vault: INERT_DOUBLES.vault,
        combineAndDecryptRunner: INERT_DOUBLES.combineAndDecryptRunner,
      },
      async () => {
        throw new Error("buildCombinerInput should NOT be called when gate blocks");
      },
    );
  }

  async function buildClearance(
    overrides?: Parameters<typeof makePorts>[0],
  ): Promise<{ clearance: GateClearance<"pre-delivery">; reader: ConcreteLiveStateReader }> {
    const ports = makePorts(overrides);
    const reader = new ConcreteLiveStateReader(ports);
    const clearance = await clearGatesAt("pre-delivery", reader, SUBJECT);
    return { clearance, reader };
  }

  it("refuses delivery when shred state == finalized", async () => {
    const coord = makeCoordinator();
    const { clearance } = await buildClearance({
      shred: { state: "finalized", post_challenge_reveal_in_progress: false },
    });
    const { queue } = makeQueue();
    await expect(
      coord.persistAndDeliver(COORDINATOR_INPUT, fakePorts(), clearance, queue),
    ).rejects.toThrow(RevealCoordinatorError);
  });

  it("refuses delivery when Art.18 freeze is active", async () => {
    const coord = makeCoordinator();
    const { clearance } = await buildClearance({ art18: { frozen: true } });
    const { queue } = makeQueue();
    await expect(
      coord.persistAndDeliver(COORDINATOR_INPUT, fakePorts(), clearance, queue),
    ).rejects.toMatchObject({
      context: { reasonCode: "REVEAL_ART18_FROZEN" },
    });
  });

  it("refuses delivery when chain RevealAuthorized is not present", async () => {
    const coord = makeCoordinator();
    const { clearance } = await buildClearance({
      chain: { reveal_authorized_present: false, confirmations: 0, authorization_block: 0 },
    });
    const { queue } = makeQueue();
    await expect(
      coord.persistAndDeliver(COORDINATOR_INPUT, fakePorts(), clearance, queue),
    ).rejects.toMatchObject({
      context: { reasonCode: "REVEAL_CHAIN_UNCONFIRMED" },
    });
  });

  it("refuses delivery when challenge window is still open", async () => {
    const coord = makeCoordinator();
    const { clearance } = await buildClearance({
      challenge: { closed: false, window_expires_at: "2099-01-01T00:00:00.000Z" },
    });
    const { queue } = makeQueue();
    await expect(
      coord.persistAndDeliver(COORDINATOR_INPUT, fakePorts(), clearance, queue),
    ).rejects.toMatchObject({
      context: { reasonCode: "REVEAL_CHALLENGE_WINDOW_OPEN" },
    });
  });

  it("refuses delivery when registry deprecation is unacceptable", async () => {
    const coord = makeCoordinator();
    const { clearance } = await buildClearance({
      registry: { acceptable: false, deprecated_refs: ["plugin/v1"] },
    });
    const { queue } = makeQueue();
    await expect(
      coord.persistAndDeliver(COORDINATOR_INPUT, fakePorts(), clearance, queue),
    ).rejects.toMatchObject({
      context: { reasonCode: "REVEAL_REGISTRY_DEPRECATED" },
    });
  });
});

describe("Adversarial construction — snapshot-once is uninhabitable", () => {
  // The compile-time proof lives in src/reveal/reveal-coordinator-impl.ts
  // (the `_ProveSnapshotOnceUntypeable` block + the ts-expect markers).
  // If tsc accepts a snapshot-once construction the ts-expect directive
  // becomes "unused" and tsc fails with TS2578 — the typecheck script in
  // package.json catches that as RC=2.
  //
  // At runtime we exercise the SECOND prong: shred state changing BETWEEN
  // clear-pre-manifest and clear-pre-delivery is detected because each
  // clearance is independently obtained from a live read. We simulate this
  // by giving the shred port a state machine.
  it("shred state change between pre-manifest and pre-delivery is caught by the live re-read", async () => {
    let shredCallCount = 0;
    const ports: LiveStateReaderPorts = {
      shred: {
        read: vi.fn(async () => {
          shredCallCount += 1;
          // First call (pre-manifest): clean.
          // Second call (pre-delivery): finalized — must trip the gate.
          if (shredCallCount === 1) {
            return { state: "none" as const, post_challenge_reveal_in_progress: false };
          }
          return { state: "finalized" as const, post_challenge_reveal_in_progress: false };
        }),
      },
      art18: { read: vi.fn(async () => ({ frozen: false })) },
      chain: {
        read: vi.fn(async () => ({
          reveal_authorized_present: true,
          confirmations: 12,
          authorization_block: 1_000_000,
        })),
      },
      challenge: {
        read: vi.fn(async () => ({ closed: true, window_expires_at: "2026-01-01T00:00:00.000Z" })),
      },
      registry: { read: vi.fn(async () => ({ acceptable: true, deprecated_refs: [] })) },
    };
    const reader = new ConcreteLiveStateReader(ports);
    const preManifest = await clearGatesAt("pre-manifest", reader, SUBJECT);
    expect(preManifest.evidence.shred.state).toBe("none");
    const preDelivery = await clearGatesAt("pre-delivery", reader, SUBJECT);
    // The pre-delivery clearance now sees finalized — defense-in-depth in
    // persistAndDeliver MUST refuse delivery.
    expect(preDelivery.evidence.shred.state).toBe("finalized");

    const coord = new RevealCoordinatorImpl(
      {
        repository: {
          upsertStatus: async () => {},
          getStatus: async () => undefined,
          putManifest: async () => {},
          getManifest: async () => undefined,
          putBundle: async () => {},
          getBundle: async () => undefined,
          listBundles: async () => [],
        },
        sigmaGatherer: INERT_DOUBLES.sigmaGatherer,
        vault: INERT_DOUBLES.vault,
        combineAndDecryptRunner: INERT_DOUBLES.combineAndDecryptRunner,
      },
      async () => {
        throw new Error("buildCombinerInput should NOT be called when gate blocks");
      },
    );
    const { queue } = makeQueue();
    await expect(
      coord.persistAndDeliver(COORDINATOR_INPUT, fakePorts(), preDelivery, queue),
    ).rejects.toMatchObject({
      context: { reasonCode: "REVEAL_SHRED_BLOCKS" },
    });
  });

  it("RevealCoordinatorPorts does NOT expose deliveryQueue (the C3a re-encode surface)", () => {
    // Compile-time: the type system has no `deliveryQueue` field on
    // RevealCoordinatorPorts. At runtime: confirm an instance synthesized from
    // the type has no such property by walking the keys via fakePorts().
    const ports = fakePorts();
    expect(Object.prototype.hasOwnProperty.call(ports, "deliveryQueue")).toBe(false);
  });
});

describe("v0.2 SHOULD-FIX-2 — provenance: buildCombinerInput cannot pass through preconditions", () => {
  // The v0.1 design accepted `Promise<Parameters<typeof
  // processRevealAuthorizedEvent>[0]>` as the callback's return type — meaning
  // the callback COULD pass through stale precondition booleans from a request
  // body, re-introducing C3a at the provenance axis silently.
  //
  // v0.2 narrows the callback's return type to
  // `Omit<EventDrivenRevealInput, "preconditions">`. The coordinator stamps
  // `preconditions` itself from `clearance.evidence`. The proof below is
  // compile-time: a constructor argument that returns the OLD shape (with
  // `preconditions`) fails to typecheck against the new constructor
  // signature.

  it("constructor refuses a buildCombinerInput callback that returns preconditions", () => {
    // We can't @ts-expect-error inside a runtime test (vitest doesn't surface
    // tsc diagnostics), so this test runs at type level via the file's own
    // typecheck. The pattern: a type-only conditional that resolves to
    // `never` if the callback signature permits a `preconditions` field, and
    // a runtime assertion that the constructor compiles with the v0.2
    // narrowed signature.
    type ConstructorParams = ConstructorParameters<typeof RevealCoordinatorImpl>;
    type CallbackReturn = Awaited<ReturnType<ConstructorParams[1]>>;
    // The narrowed return type excludes `preconditions`. If a regression
    // widens the callback, this typeof assertion would resolve to `true`
    // (preconditions present), and the const-init line below would fail to
    // typecheck.
    type PreconditionsPresentInReturn = "preconditions" extends keyof CallbackReturn ? true : false;
    const proof: PreconditionsPresentInReturn = false;
    expect(proof).toBe(false);
  });
});

describe("v0.2 SHOULD-FIX-1 — time TOCTOU: per-enqueue re-clearance", () => {
  // v0.1 minted a single pre-delivery clearance at the route handler, then
  // ran buildCombinerInput + processRevealAuthorizedEvent + per-bundle
  // enqueue in sequence. A shred-finalized or Art.18-freeze event during any
  // of those awaits would slip through because no re-validation happened
  // between clearance mint and enqueue side-effects.
  //
  // v0.2 re-mints `GateClearance<"pre-delivery">` IMMEDIATELY before each
  // enqueue via `ports.clearGatesAt` and re-runs
  // `assertClearanceAllowsDelivery`. The TOCTOU window per enqueue is
  // bounded to one Promise.all over five live reads.
  //
  // The test below witnesses this by constructing a LiveStateReader whose
  // shred port flips from "none" to "finalized" between the entry clearance
  // mint (1st read) and the per-enqueue re-mint (2nd read). The entry
  // clearance is clean; the re-mint produces a blocking clearance; the
  // bundle is dead-lettered rather than enqueued. We exercise this without
  // running the real combiner by using a coordinator whose
  // `buildCombinerInput` and stubbed deps never actually engage
  // processRevealAuthorizedEvent for the gate-fail path.

  it("re-clearance occurs INSIDE persistAndDeliver — port called more than once per request", async () => {
    // Construct a stateful shred port that counts reads. The entry mint at
    // the route handler is one read; the per-enqueue re-mint inside
    // persistAndDeliver is another read. Without the v0.2 fix, the shred
    // port would only be hit ONCE per request.
    let shredCallCount = 0;
    const ports: LiveStateReaderPorts = {
      shred: {
        read: vi.fn(async () => {
          shredCallCount += 1;
          return { state: "none" as const, post_challenge_reveal_in_progress: false };
        }),
      },
      art18: { read: vi.fn(async () => ({ frozen: false })) },
      chain: {
        read: vi.fn(async () => ({
          reveal_authorized_present: true,
          confirmations: 12,
          authorization_block: 1_000_000,
        })),
      },
      challenge: {
        read: vi.fn(async () => ({ closed: true, window_expires_at: "2026-01-01T00:00:00.000Z" })),
      },
      registry: { read: vi.fn(async () => ({ acceptable: true, deprecated_refs: [] })) },
    };
    const reader = new ConcreteLiveStateReader(ports);
    const portsForCoord: RevealCoordinatorPorts = {
      liveState: reader,
      clearGatesAt,
      anchor: {
        anchor: async () => ({ commit_tx_hash: "0x" + "0".repeat(64), commit_block: 1_000_000, attempts: 1 }),
      },
    };

    // Coordinator whose combiner stub returns ONE synthetic bundle.
    const coord = makeStubCoordinatorWithOneBundle();

    // Entry clearance (the route handler would mint this).
    const entryClearance = await clearGatesAt("pre-delivery", reader, SUBJECT);
    expect(shredCallCount).toBe(1);

    const { queue, enqueued } = makeQueue();
    await coord.persistAndDeliver(COORDINATOR_INPUT, portsForCoord, entryClearance, queue);

    // The single bundle should have been enqueued AND the shred port should
    // have been hit AT LEAST twice (entry + per-enqueue re-mint). With the
    // v0.1 design, shredCallCount would stay at 1.
    expect(enqueued.length).toBe(1);
    expect(shredCallCount).toBeGreaterThanOrEqual(2);
  });

  it("dead-letters a bundle when shred state flips between entry-clear and per-enqueue re-mint", async () => {
    let shredCallCount = 0;
    const ports: LiveStateReaderPorts = {
      shred: {
        read: vi.fn(async () => {
          shredCallCount += 1;
          // Entry-clear (call #1): clean.
          // Per-enqueue re-mint (call #2): shred finalized — re-clearance
          // must refuse and the bundle must be dead-lettered.
          if (shredCallCount === 1) {
            return { state: "none" as const, post_challenge_reveal_in_progress: false };
          }
          return { state: "finalized" as const, post_challenge_reveal_in_progress: false };
        }),
      },
      art18: { read: vi.fn(async () => ({ frozen: false })) },
      chain: {
        read: vi.fn(async () => ({
          reveal_authorized_present: true,
          confirmations: 12,
          authorization_block: 1_000_000,
        })),
      },
      challenge: {
        read: vi.fn(async () => ({ closed: true, window_expires_at: "2026-01-01T00:00:00.000Z" })),
      },
      registry: { read: vi.fn(async () => ({ acceptable: true, deprecated_refs: [] })) },
    };
    const reader = new ConcreteLiveStateReader(ports);
    const portsForCoord: RevealCoordinatorPorts = {
      liveState: reader,
      clearGatesAt,
      anchor: {
        anchor: async () => ({ commit_tx_hash: "0x" + "0".repeat(64), commit_block: 1_000_000, attempts: 1 }),
      },
    };

    const coord = makeStubCoordinatorWithOneBundle();
    const entryClearance = await clearGatesAt("pre-delivery", reader, SUBJECT);

    const { queue, enqueued, deadLettered } = makeQueue();
    await coord.persistAndDeliver(COORDINATOR_INPUT, portsForCoord, entryClearance, queue);

    // Nothing enqueued — the bundle was dead-lettered because re-clearance refused.
    expect(enqueued.length).toBe(0);
    expect(deadLettered.length).toBe(1);
    expect(deadLettered[0]?.reason ?? "").toMatch(/pre-delivery re-clearance failed/);
  });
});

// ─── Local helpers ─────────────────────────────────────────────────────────

function fakePorts(): RevealCoordinatorPorts {
  return {
    liveState: new ConcreteLiveStateReader(makePorts()),
    clearGatesAt,
    anchor: {
      anchor: async () => ({
        commit_tx_hash: "0x" + "0".repeat(64),
        commit_block: 1_000_000,
        attempts: 1,
      }),
    },
  };
}

/**
 * Coordinator whose combiner stub returns exactly one synthetic
 * RevealArtifactBundle. The repository accepts any putBundle; buildCombinerInput
 * returns a minimal partial that satisfies the v0.2 narrowed signature.
 *
 * Used by the v0.2 SHOULD-FIX-1 tests to exercise the per-enqueue re-clear
 * path without engaging the real combiner-orchestrator's manifest + bundle
 * + sigma surface (those are covered by tests/integration/reveal-* and live
 * in lower-level packages' tests).
 */
function makeStubCoordinatorWithOneBundle(): RevealCoordinatorImpl {
  const oneBundle = makeSyntheticBundle();
  // Setter erases generics intentionally (see vi.mock at file top).
  type ProcessRevealStub = (input: unknown, deps: unknown) => Promise<EventDrivenRevealResult>;
  const stub: ProcessRevealStub = async () => ({
    status: "finalized",
    manifest: {} as EventDrivenRevealResult["manifest"],
    bundles: [oneBundle],
    failed_recipients: [],
  });
  (globalThis as unknown as { __setProcessRevealStub: (s: ProcessRevealStub) => void }).__setProcessRevealStub(stub);
  return new RevealCoordinatorImpl(
    {
      repository: {
        upsertStatus: async () => {},
        getStatus: async () => undefined,
        putManifest: async () => {},
        getManifest: async () => undefined,
        putBundle: async () => {},
        getBundle: async () => undefined,
        listBundles: async () => [],
      },
      sigmaGatherer: INERT_DOUBLES.sigmaGatherer,
      vault: INERT_DOUBLES.vault,
      combineAndDecryptRunner: INERT_DOUBLES.combineAndDecryptRunner,
    },
    async () => makePartialCombinerInput(),
  );
}

function makeSyntheticBundle(): RevealArtifactBundle {
  return {
    bundle_version: "s2-5.1",
    canonicalization: {
      format: "JCS",
      rfc: "RFC8785",
      hash: "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))",
    },
    authorization: {
      authorizationId: H32_A,
      h_commit: H32_B,
      commit_version: "0x0302",
      authorization_block: 1_000_000,
      authorization_block_hash: H32_A,
      authorization_timestamp: "2026-05-19T12:00:00.000Z",
      conditionRef: H32_A,
      challenge_window_seconds: 3600,
      challenge_window_expired_at: "2026-05-19T13:00:00.000Z",
      finalized_at: "2026-05-19T14:00:00.000Z",
    },
    pda: {
      pda_id: "test-pda",
      pda_version: "1",
      pda_root: H32_B,
      trust_tier: "T2" as RevealArtifactBundle["pda"]["trust_tier"],
      operational_class: "C2" as RevealArtifactBundle["pda"]["operational_class"],
    },
    recipient: {
      recipient_ref: "partner-test",
      schema_selector_digest: H32_A,
    },
    plaintext: {
      schema_selector_digest: H32_A,
      schema_digest: H32_B,
      content_encoding: "application/json",
    },
    issuer_attestation: {} as RevealArtifactBundle["issuer_attestation"],
    provenance: {} as RevealArtifactBundle["provenance"],
    sigma_block: {} as RevealArtifactBundle["sigma_block"],
    chain_proofs: {} as RevealArtifactBundle["chain_proofs"],
    registry_snapshots: {} as RevealArtifactBundle["registry_snapshots"],
    shred_state: {} as RevealArtifactBundle["shred_state"],
    sd_refs: { status: "not_configured" } as RevealArtifactBundle["sd_refs"],
    verification: {
      artifact_bundle_digest: H32_A,
      verifier_version: "s2-5.1-test-stub",
    },
    pii_statement: "recipient_filtered_plaintext_after_valid_reveal",
  };
}

function makePartialCombinerInput(): Omit<EventDrivenRevealInput, "preconditions"> {
  // Minimal valid shape; the stubbed processRevealAuthorizedEvent does not
  // inspect most fields. We populate fields necessary for the coordinator's
  // own use (recipient_selectors.length > 0 drives recipient_policy_identified).
  return {
    event: {
      authorizationId: H32_A,
      h_commit: H32_B,
      authorization_block: 1_000_000n,
      authorization_timestamp: 1747800000n,
      challenge_window: 3600,
      conditionRef: H32_A,
      pda_root: H32_B,
    } as EventDrivenRevealInput["event"],
    partner_id: "test-partner",
    pda: {
      pda_id: "test-pda",
      pda_version: "1",
      trust_tier: "T2" as EventDrivenRevealInput["pda"]["trust_tier"],
      operational_class: "C2" as EventDrivenRevealInput["pda"]["operational_class"],
    },
    g3_choice: "drand",
    g4_phase: 2,
    schema_digest: H32_B,
    // F-API-1: the input carries a combiner_input REFERENCE, not cleartext. The
    // stubbed processRevealAuthorizedEvent (vi.mock at file top) never inspects
    // it, so the inert double's reference satisfies the type.
    combiner_input: INERT_DOUBLES.combinerInput,
    recipient_selectors: [
      {
        recipient_ref: "partner-test",
        schema_selector_digest: H32_A,
      } as EventDrivenRevealInput["recipient_selectors"][number],
    ],
    sigma_block: {} as EventDrivenRevealInput["sigma_block"],
    chain_proofs: {} as EventDrivenRevealInput["chain_proofs"],
    registry_snapshots: {} as EventDrivenRevealInput["registry_snapshots"],
    shred_state: {} as EventDrivenRevealInput["shred_state"],
    sd_refs: { status: "not_configured" } as EventDrivenRevealInput["sd_refs"],
    gate_endpoints: {},
    registry_snapshot_refs: {},
    recipient_policy: {},
  };
}
