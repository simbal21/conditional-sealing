// T3.2 tests — Production `SigmaGatherer` (F-API-1 part 1).
//
// Coverage:
//   1. Canonical ordering Lit → G3 → G4 (FIXED_ONLY) and with conditional
//      recipients (RECIPIENT_K_OF_N).
//   2. G3 routing by PDA `g3_choice` (dcipher vs drand) — PLATFORM PRINCIPLE.
//   3. Missing-gate → fail-closed (no silent bundle shrink).
//   4. The F4 seam: `metadata.verified` is bound to the ACTUAL verifySigma
//      result — a gate whose verifySigma returns `ok:false` (or throws) causes
//      fail-closed; the flag is never a trusted label.
//   5. requestSigma is called exactly once per gate; verifySigma exactly once.
//   6. Absent gate-recipient pubkey → fail-closed.
//   7. Downstream acceptance: the produced bundle passes the M3 combiner's
//      `orchestrateSigmas` ordering + verified-flag + share-recovery checks for
//      a FIXED_ONLY profile (proves stanzaIndex + verified + order are all
//      combiner-correct, not just self-consistent).

import { describe, expect, it } from "vitest";
import {
  ProductionSigmaGatherer,
  createProductionSigmaGatherer,
  SigmaGatherError,
  type GateSigningClient,
  type SigmaGatherClients,
  type SigmaGatherContext,
  type SigmaGatheringRequest,
} from "../../src/combiner-orchestrator/sigma-gathering.js";
import {
  GateKind,
  orchestrateSigmas,
  zeroCommitAADInput,
  type AccessStructureProfile,
  type GateKind as GateKindType,
  type GateRecipientPubkeyEntry,
  type RequestSigmaInput,
  type RequestSigmaResult,
  type VerifySigmaResult,
} from "../../src/m3-imports.js";
import type { Hex32 } from "../../src/types/reveal-artifact-bundle.js";

const hex32 = (seed: string): Hex32 => `0x${seed.repeat(64).slice(0, 64)}` as Hex32;

const AUTH_ID = hex32("a1");
const H_COMMIT = hex32("b2");
const BLOCK_HASH = hex32("c3");
const AUTH_BLOCK = 1000n;
const COMMIT_BLOCK = 900n;

/** A 32-byte share-hex so the downstream combiner's share recovery succeeds. */
const SHARE_HEX = `0x${"11".repeat(32)}` as Hex32;

interface CallLog {
  requestCount: number;
  verifyCount: number;
  lastRequestInput?: RequestSigmaInput<unknown>;
  lastVerifySigma?: Uint8Array;
}

/**
 * Deterministic gate-client double. `verify` controls the verifySigma outcome;
 * `requestExtraMetadata` lets a test inject gate-supplied metadata (e.g. a
 * pre-set `verified: "false"` to prove the gatherer overrides it from the real
 * verify result).
 */
function makeGateClient(
  gateKind: GateKindType,
  opts: {
    readonly verify?: VerifySigmaResult;
    readonly verifyThrows?: boolean;
    readonly requestThrows?: boolean;
    readonly requestExtraMetadata?: Readonly<Record<string, string | number | bigint | Hex32>>;
    readonly log?: CallLog;
  } = {},
): GateSigningClient {
  const log = opts.log;
  const sigmaByte = Number(gateKind) + 1;
  return {
    gateKind,
    async requestSigma(
      input: RequestSigmaInput<unknown>,
    ): Promise<RequestSigmaResult & { sigma: Uint8Array }> {
      if (log) {
        log.requestCount += 1;
        log.lastRequestInput = input;
      }
      if (opts.requestThrows) throw new Error(`request boom ${String(gateKind)}`);
      return {
        sigma: new Uint8Array([sigmaByte, sigmaByte, sigmaByte]),
        gateKind,
        metadata: {
          // Gate-supplied share material (in production the gate's stanza
          // decapsulation output). Threaded through by the gatherer.
          shareHex: SHARE_HEX,
          // A gate that mischievously pre-claims verification — the gatherer
          // MUST override this from its own verifySigma result.
          verified: "false",
          ...opts.requestExtraMetadata,
        },
      };
    },
    async verifySigma(
      input: RequestSigmaInput<unknown> & { sigma: Uint8Array },
    ): Promise<VerifySigmaResult> {
      if (log) {
        log.verifyCount += 1;
        log.lastVerifySigma = input.sigma;
      }
      if (opts.verifyThrows) throw new Error(`verify boom ${String(gateKind)}`);
      return opts.verify ?? { ok: true };
    },
  };
}

function makeRecipientPubkey(
  gateKind: GateKindType,
  conditionalRecipientIndex: number,
): GateRecipientPubkeyEntry {
  return {
    authorizationId: AUTH_ID,
    gateKind,
    conditionalRecipientIndex,
    kemPubkey: new Uint8Array([Number(gateKind)]),
    attestationRef: hex32("ee"),
    effectiveBlock: 0n,
    tombstoneBlock: 0n,
    perCommitEphemeral: gateKind !== GateKind.Drand,
  };
}

function pubkeyMap(
  entries: readonly { kind: GateKindType; cri: number }[],
): ReadonlyMap<string, GateRecipientPubkeyEntry> {
  const map = new Map<string, GateRecipientPubkeyEntry>();
  for (const { kind, cri } of entries) {
    map.set(`${kind}:${cri}`, makeRecipientPubkey(kind, cri));
  }
  return map;
}

function makeRequest(g3_choice: "dcipher" | "drand"): SigmaGatheringRequest {
  return {
    authorizationId: AUTH_ID,
    h_commit: H_COMMIT,
    partner_id: "11111111-1111-4111-8111-111111111111",
    pda_id: "22222222-2222-4222-8222-222222222222",
    g3_choice,
  };
}

function makeContext(
  profile: AccessStructureProfile,
  pubkeys: ReadonlyMap<string, GateRecipientPubkeyEntry>,
): SigmaGatherContext {
  return {
    authorizationBlock: AUTH_BLOCK,
    commitBlock: COMMIT_BLOCK,
    blockHash: BLOCK_HASH,
    profile,
    gateRecipientPubkeys: pubkeys,
  };
}

const FIXED_ONLY: AccessStructureProfile = { kind: "FIXED_ONLY" };

describe("ProductionSigmaGatherer — canonical ordering", () => {
  it("emits Lit → Dcipher → G4 in order for FIXED_ONLY + g3_choice=dcipher", async () => {
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    const bundle = await gatherer.gatherSigmas(makeRequest("dcipher"));

    expect(bundle.authorizationId).toBe(AUTH_ID);
    expect(bundle.hCommit).toBe(H_COMMIT);
    expect(bundle.authorizationBlock).toBe(AUTH_BLOCK);
    expect(bundle.commitBlock).toBe(COMMIT_BLOCK);
    expect(bundle.evidence.map((e) => e.gateKind)).toEqual([
      GateKind.LitV3,
      GateKind.Dcipher,
      GateKind.G4,
    ]);
    // stanzaIndex stamped authoritatively in positional order.
    expect(bundle.evidence.map((e) => e.metadata.stanzaIndex)).toEqual([0, 1, 2]);
  });

  it("routes G3 to drand when g3_choice=drand (PLATFORM PRINCIPLE)", async () => {
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3),
      drand: makeGateClient(GateKind.Drand),
      g4: makeGateClient(GateKind.G4),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Drand, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    const bundle = await gatherer.gatherSigmas(makeRequest("drand"));

    expect(bundle.evidence.map((e) => e.gateKind)).toEqual([
      GateKind.LitV3,
      GateKind.Drand,
      GateKind.G4,
    ]);
  });

  it("appends conditional-recipient σ slots after G4 for RECIPIENT_K_OF_N", async () => {
    const profile: AccessStructureProfile = {
      kind: "RECIPIENT_K_OF_N",
      n_conditional: 3,
      k_conditional: 2,
    };
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
      conditionalRecipients: [
        makeGateClient(GateKind.ConditionalRecipient),
        makeGateClient(GateKind.ConditionalRecipient),
      ],
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
      { kind: GateKind.ConditionalRecipient, cri: 0 },
      { kind: GateKind.ConditionalRecipient, cri: 1 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(profile, pubkeys),
    });

    const bundle = await gatherer.gatherSigmas(makeRequest("dcipher"));

    expect(bundle.evidence.map((e) => e.gateKind)).toEqual([
      GateKind.LitV3,
      GateKind.Dcipher,
      GateKind.G4,
      GateKind.ConditionalRecipient,
      GateKind.ConditionalRecipient,
    ]);
    expect(bundle.evidence.map((e) => e.conditionalRecipientIndex)).toEqual([0, 0, 0, 0, 1]);
    expect(bundle.evidence.map((e) => e.metadata.stanzaIndex)).toEqual([0, 1, 2, 3, 4]);
  });
});

describe("ProductionSigmaGatherer — F4 seam: verified flag bound to real verification", () => {
  it("overrides a gate-supplied verified:false with verified:true from a passing verifySigma", async () => {
    // The client's requestSigma returns metadata.verified === "false". The
    // gatherer's own verifySigma passes → the emitted evidence must carry
    // verified === "true" (from the REAL verify), NOT the gate's claimed value.
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3, { requestExtraMetadata: { verified: "false" } }),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    const bundle = await gatherer.gatherSigmas(makeRequest("dcipher"));

    for (const e of bundle.evidence) {
      expect(e.metadata.verified).toBe("true");
      expect(e.metadata.verifyCode).toBe("ok");
    }
  });

  it("fails closed when a gate's verifySigma returns ok:false (never stamps verified:true)", async () => {
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3),
      // G4 σ is structurally returned but verification rejects it.
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4, {
        verify: { ok: false, code: "CUSTODY_ERR_G4_REFUSED", detail: "attestation stale" },
      }),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    await expect(gatherer.gatherSigmas(makeRequest("dcipher"))).rejects.toMatchObject({
      name: "SigmaGatherError",
      code: "CUSTODY_ERR_G4_REFUSED",
      gateKind: GateKind.G4,
    });
  });

  it("fails closed when a gate's verifySigma throws", async () => {
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3),
      dcipher: makeGateClient(GateKind.Dcipher, { verifyThrows: true }),
      g4: makeGateClient(GateKind.G4),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    await expect(gatherer.gatherSigmas(makeRequest("dcipher"))).rejects.toMatchObject({
      name: "SigmaGatherError",
      code: "GATE_VERIFY_THREW",
    });
  });

  it("calls requestSigma once and verifySigma once per gate, verifying the same σ that was requested", async () => {
    const litLog: CallLog = { requestCount: 0, verifyCount: 0 };
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3, { log: litLog }),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    await gatherer.gatherSigmas(makeRequest("dcipher"));

    expect(litLog.requestCount).toBe(1);
    expect(litLog.verifyCount).toBe(1);
    // The σ verified is the σ that was requested (Lit's deterministic bytes).
    expect(Array.from(litLog.lastVerifySigma ?? [])).toEqual([1, 1, 1]);
  });
});

describe("ProductionSigmaGatherer — fail-closed on missing inputs", () => {
  it("rejects when the PDA-selected G3 client is not injected", async () => {
    // g3_choice=drand but only a dcipher client is wired → fail-closed.
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Drand, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    await expect(gatherer.gatherSigmas(makeRequest("drand"))).rejects.toMatchObject({
      name: "SigmaGatherError",
      code: "GATE_CLIENT_MISSING",
      gateKind: GateKind.Drand,
    });
  });

  it("rejects when too few conditional-recipient clients are injected for the profile", async () => {
    const profile: AccessStructureProfile = {
      kind: "RECIPIENT_K_OF_N",
      n_conditional: 3,
      k_conditional: 2,
    };
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
      conditionalRecipients: [makeGateClient(GateKind.ConditionalRecipient)], // only 1, need 2
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
      { kind: GateKind.ConditionalRecipient, cri: 0 },
      { kind: GateKind.ConditionalRecipient, cri: 1 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(profile, pubkeys),
    });

    await expect(gatherer.gatherSigmas(makeRequest("dcipher"))).rejects.toMatchObject({
      name: "SigmaGatherError",
      code: "GATE_CLIENT_MISSING",
      gateKind: GateKind.ConditionalRecipient,
    });
  });

  it("rejects a client whose gateKind does not match its slot", async () => {
    const clients: SigmaGatherClients = {
      // Wrong: a G4 client wired into the lit slot.
      lit: makeGateClient(GateKind.G4),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    await expect(gatherer.gatherSigmas(makeRequest("dcipher"))).rejects.toMatchObject({
      name: "SigmaGatherError",
      code: "GATE_CLIENT_MISMATCH",
    });
  });

  it("rejects when a gate-recipient pubkey is absent at the authorization block", async () => {
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
    };
    // Lit pubkey deliberately omitted.
    const pubkeys = pubkeyMap([
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    await expect(gatherer.gatherSigmas(makeRequest("dcipher"))).rejects.toMatchObject({
      name: "SigmaGatherError",
      code: "GATE_RECIPIENT_PUBKEY_ABSENT",
      gateKind: GateKind.LitV3,
    });
  });

  it("fails closed when a gate's requestSigma throws", async () => {
    const clients: SigmaGatherClients = {
      lit: makeGateClient(GateKind.LitV3, { requestThrows: true }),
      dcipher: makeGateClient(GateKind.Dcipher),
      g4: makeGateClient(GateKind.G4),
    };
    const pubkeys = pubkeyMap([
      { kind: GateKind.LitV3, cri: 0 },
      { kind: GateKind.Dcipher, cri: 0 },
      { kind: GateKind.G4, cri: 0 },
    ]);
    const gatherer = new ProductionSigmaGatherer({
      clients,
      resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
    });

    await expect(gatherer.gatherSigmas(makeRequest("dcipher"))).rejects.toMatchObject({
      name: "SigmaGatherError",
      code: "GATE_REQUEST_FAILED",
      gateKind: GateKind.LitV3,
    });
  });
});

describe("ProductionSigmaGatherer — downstream M3 combiner acceptance", () => {
  it("produces a bundle the combiner's orchestrateSigmas accepts (ordering + verified + share recovery) for FIXED_ONLY", () => {
    return runDownstreamAcceptance("dcipher", 0);
  });

  it("produces a combiner-accepted bundle with g3_choice=drand", () => {
    return runDownstreamAcceptance("drand", 1);
  });
});

async function runDownstreamAcceptance(
  g3_choice: "dcipher" | "drand",
  g3ChoiceByte: 0 | 1,
): Promise<void> {
  const g3Kind = g3_choice === "dcipher" ? GateKind.Dcipher : GateKind.Drand;
  const clients: SigmaGatherClients =
    g3_choice === "dcipher"
      ? {
          lit: makeGateClient(GateKind.LitV3),
          dcipher: makeGateClient(GateKind.Dcipher),
          g4: makeGateClient(GateKind.G4),
        }
      : {
          lit: makeGateClient(GateKind.LitV3),
          drand: makeGateClient(GateKind.Drand),
          g4: makeGateClient(GateKind.G4),
        };
  const pubkeys = pubkeyMap([
    { kind: GateKind.LitV3, cri: 0 },
    { kind: g3Kind, cri: 0 },
    { kind: GateKind.G4, cri: 0 },
  ]);
  const gatherer = createProductionSigmaGatherer({
    clients,
    resolveContext: () => makeContext(FIXED_ONLY, pubkeys),
  });

  const bundle = await gatherer.gatherSigmas(makeRequest(g3_choice));

  const commitAAD = { ...zeroCommitAADInput(), g3_choice: g3ChoiceByte };

  // orchestrateSigmas runs: assertBundleIdentity → assertFixedOrdering →
  // (per evidence) assertSigmaVerified → recoverShareFromEvidence →
  // assertStanzaIndex. All must pass with the gatherer's output.
  const result = orchestrateSigmas({
    authorizationId: AUTH_ID,
    hCommit: H_COMMIT,
    authorizationBlock: AUTH_BLOCK,
    blockHash: BLOCK_HASH,
    commitAAD,
    profile: FIXED_ONLY,
    sigmas: bundle,
  });

  expect(result.admittedShares).toHaveLength(3);
  expect(result.evidence.map((e) => e.gate)).toEqual(["LitV3", g3_choice === "dcipher" ? "Dcipher" : "Drand", "G4"]);
  expect(result.evidence.map((e) => e.stanzaIndex)).toEqual([0, 1, 2]);
}

describe("SigmaGatherError", () => {
  it("is an Error subclass carrying code + optional gateKind", () => {
    const err = new SigmaGatherError("X_CODE", "msg", GateKind.G4);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("SigmaGatherError");
    expect(err.code).toBe("X_CODE");
    expect(err.gateKind).toBe(GateKind.G4);
  });
});
