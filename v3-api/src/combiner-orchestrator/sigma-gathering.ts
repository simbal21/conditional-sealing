// T3.2 — σ gathering: interface + production `SigmaGatherer` (F-API-1 part 1).
//
// PURPOSE
// -------
// Collect the per-gate σ values for one authorized reveal and assemble them
// into the `SigmaEvidenceBundle` the M3 combiner consumes. The gatherer runs
// AFTER on-chain `RevealAuthorized` has fired (the event listener drives it);
// it asks each participating gate to sign σ for the `authorizationId` exactly
// once, runs a REAL `verifySigma` against each returned σ, and emits the
// evidence in the canonical fixed order the combiner's `orchestrateSigmas`
// enforces:
//
//     Lit(0)  →  G3(0)  →  G4(0)  →  ConditionalRecipient(0..k-1)
//
// where G3 is `Dcipher` or `Drand` per the PDA's `g3_choice` (PLATFORM
// PRINCIPLE — nothing hardcoded; the PDA selects which G3 gate signs).
//
// THE F4 SEAM (closed here)
// -------------------------
// `SigmaEvidence.metadata.verified` is the combiner's PRIMARY gate-authorization
// check — `@cealis/v3-custody` `combiner/sigma-orchestrator.ts assertSigmaVerified`
// fail-CLOSED requires `verified === "true"`. A gatherer that stamped
// `verified: "true"` as a TRUSTED LABEL — without actually verifying — would let
// an unverified σ flow straight into DEK reconstruction. This impl binds the
// flag to the result of a real `verifySigma(...)` call on the gate adapter; if
// verification fails the gate is rejected (fail-closed), never down-graded to a
// stamped label. The gatherer is authoritative for `verified` / `verifyCode` /
// `stanzaIndex`, so a misbehaving client cannot pre-set `verified` itself.
//
// EXTERNAL-GATE BOUNDARY (build TO, do NOT cross — Phase-3 plan §6)
// ----------------------------------------------------------------
// The real network gate clients (Lit V3 Chipotle SDK, dcipher committee, drand
// League-of-Entropy, the G4 TEE daemon) are vendor/infra-gated. This gatherer
// depends ONLY on the abstract `GateSigningClient` port (a narrowed view of M3's
// `GateAdapter`: `requestSigma` + `verifySigma`). Phase 3 wires the real
// `@cealis/v3-custody` adapters into `SigmaGatherClients`; tests inject a
// deterministic double behind the same port. The gatherer itself crosses no
// vendor boundary — it is pure orchestration over the injected clients.

import type {
  AccessStructureProfile,
  GateKind as GateKindType,
  GateRecipientPubkeyEntry,
  RequestSigmaInput,
  RequestSigmaResult,
  SigmaEvidence,
  SigmaEvidenceBundle,
  VerifySigmaResult,
} from "../m3-imports.js";
import { GateKind } from "../m3-imports.js";
import type { WebhookEnvelope } from "../types/webhook-events.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

export interface SigmaGatheringRequest {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly partner_id: string;
  readonly pda_id: string;
  /** PDA-selected G3 gate (PLATFORM PRINCIPLE — never hardcoded). */
  readonly g3_choice: "dcipher" | "drand";
}

export interface SigmaGatherer {
  gatherSigmas(request: SigmaGatheringRequest): Promise<SigmaEvidenceBundle>;
}

export interface SigmaGatheringEventBus {
  emit(event: WebhookEnvelope<Record<string, unknown>>): Promise<void> | void;
}

export async function gatherSigmasForReveal(
  request: SigmaGatheringRequest,
  deps: {
    readonly gatherer: SigmaGatherer;
    readonly eventBus?: SigmaGatheringEventBus;
    readonly now?: () => Date;
  },
): Promise<SigmaEvidenceBundle> {
  const createdAt = (deps.now?.() ?? new Date()).toISOString();
  await deps.eventBus?.emit({
    event_id: `${request.authorizationId}:ready_for_gate_signing`,
    schema_version: "s2-5.1",
    event_type: "reveal.ready_for_gate_signing",
    created_at: createdAt,
    partner_id: request.partner_id,
    pda_id: request.pda_id,
    data: {
      authorizationId: request.authorizationId,
      h_commit: request.h_commit,
    },
  });
  return deps.gatherer.gatherSigmas(request);
}

// ---------------------------------------------------------------------------
// Production SigmaGatherer impl
// ---------------------------------------------------------------------------

/**
 * Narrowed gate-client port the gatherer depends on. This is the
 * request+verify subset of M3's `GateAdapter` — exactly what the gatherer
 * needs and nothing more (no `prepareCommitBinding`, a commit-time concern; no
 * `healthProbe`, an SRE-cadence concern).
 *
 * Real impls: `@cealis/v3-custody` `createLitAdapter` / `createDcipherAdapter` /
 * `createDrandAdapter` / `createG4Phase1Adapter` / `createG4Phase2Adapter`
 * (vendor-gated network clients). Test impls: deterministic doubles.
 *
 * `σ` is opaque `Uint8Array` at the gatherer boundary; gate-specific `extras`
 * are forwarded unchanged.
 */
export interface GateSigningClient {
  readonly gateKind: GateKindType;
  requestSigma(
    input: RequestSigmaInput<unknown>,
  ): Promise<RequestSigmaResult & { sigma: Uint8Array }>;
  verifySigma(
    input: RequestSigmaInput<unknown> & { sigma: Uint8Array },
  ): Promise<VerifySigmaResult>;
}

/**
 * The injected set of gate clients. `lit` and `g4` are always present (every
 * profile binds them top-level). G3 is `dcipher` OR `drand` per PDA `g3_choice`
 * — at least the chosen one MUST be present. `conditionalRecipients` supplies
 * one client per conditional-recipient slot for `RECIPIENT_1_OF_1` /
 * `RECIPIENT_K_OF_N` profiles (empty/absent for `FIXED_ONLY`).
 */
export interface SigmaGatherClients {
  readonly lit: GateSigningClient;
  readonly dcipher?: GateSigningClient;
  readonly drand?: GateSigningClient;
  readonly g4: GateSigningClient;
  readonly conditionalRecipients?: readonly GateSigningClient[];
}

/**
 * Per-authorization on-chain context the gatherer needs to build a faithful
 * `RequestSigmaInput`. The reveal event carries these; the composition root
 * threads them in. The gate-recipient pubkey entries (one per participating
 * gate, recovered from `GateRecipientPubkeyRegistry` at the authorization
 * block) populate `SigmaEvidence.gateRecipientPubkey`.
 */
export interface SigmaGatherContext {
  readonly authorizationBlock: bigint;
  readonly commitBlock: bigint;
  readonly blockHash: Hex32;
  /** Access-structure profile (drives whether conditional-recipient σ is required). */
  readonly profile: AccessStructureProfile;
  /**
   * Gate-recipient pubkey entries keyed by `${gateKind}:${conditionalRecipientIndex}`
   * — the canonical key the combiner's snapshot map uses. Recovered live at the
   * authorization block by the chain reader (no cache — C3a discipline).
   */
  readonly gateRecipientPubkeys: ReadonlyMap<string, GateRecipientPubkeyEntry>;
  /** Gate-specific extras forwarded to `requestSigma`/`verifySigma`, keyed the same way. */
  readonly gateExtras?: ReadonlyMap<string, unknown>;
}

/**
 * Error thrown by the gatherer on any fail-closed condition (missing gate,
 * absent recipient pubkey, failed verification, client error). Carries a stable
 * `code` for the combiner-orchestrator to map to a `CUSTODY_ERR_*` class.
 */
export class SigmaGatherError extends Error {
  readonly code: string;
  readonly gateKind?: GateKindType;
  constructor(code: string, message: string, gateKind?: GateKindType) {
    super(message);
    this.name = "SigmaGatherError";
    this.code = code;
    this.gateKind = gateKind;
  }
}

const pubkeyKey = (gateKind: GateKindType, conditionalRecipientIndex: number): string =>
  `${gateKind}:${conditionalRecipientIndex}`;

const gateLabel = (gateKind: GateKindType): string => {
  switch (gateKind) {
    case GateKind.LitV3:
      return "LitV3";
    case GateKind.Dcipher:
      return "Dcipher";
    case GateKind.Drand:
      return "Drand";
    case GateKind.G4:
      return "G4";
    case GateKind.ConditionalRecipient:
      return "ConditionalRecipient";
    default:
      return `Gate#${String(gateKind)}`;
  }
};

/**
 * One required gate slot in the canonical sequence: which client signs, which
 * `GateKind`, and the conditional-recipient index. `stanzaIndex` is the slot's
 * position in the canonical order — the combiner cross-checks the σ's
 * `metadata.stanzaIndex` against this, so the gatherer stamps it authoritatively.
 */
interface RequiredGateSlot {
  readonly client: GateSigningClient;
  readonly gateKind: GateKindType;
  readonly conditionalRecipientIndex: number;
  readonly stanzaIndex: number;
}

function conditionalRecipientCount(profile: AccessStructureProfile): number {
  switch (profile.kind) {
    case "FIXED_ONLY":
      return 0;
    case "RECIPIENT_1_OF_1":
      return 1;
    case "RECIPIENT_K_OF_N":
      return profile.k_conditional;
    default:
      return 0;
  }
}

function requireClient(
  client: GateSigningClient | undefined,
  expected: GateKindType,
): GateSigningClient {
  if (client === undefined) {
    throw new SigmaGatherError(
      "GATE_CLIENT_MISSING",
      `no gate client injected for ${gateLabel(expected)}`,
      expected,
    );
  }
  if (client.gateKind !== expected) {
    throw new SigmaGatherError(
      "GATE_CLIENT_MISMATCH",
      `gate client kind mismatch: expected ${gateLabel(expected)}, got ${gateLabel(client.gateKind)}`,
      expected,
    );
  }
  return client;
}

/**
 * Build the canonical required-gate sequence for a reveal: Lit → G3 → G4 →
 * conditional-recipient slots. G3 resolves to the dcipher OR drand client per
 * `g3_choice`. Mirrors the combiner's `requiredGateSequence` so the bundle the
 * gatherer produces matches the ordering the combiner enforces.
 *
 * Fail-closed: a missing client for any required slot raises
 * `GATE_CLIENT_MISSING` rather than silently shrinking the bundle (which would
 * weaken the 4-gate AND-composition).
 */
function buildRequiredSequence(
  clients: SigmaGatherClients,
  g3Choice: SigmaGatheringRequest["g3_choice"],
  profile: AccessStructureProfile,
): readonly RequiredGateSlot[] {
  const slots: RequiredGateSlot[] = [];
  let stanzaIndex = 0;

  // 1. Lit V3 (top-level, always required).
  slots.push({
    client: requireClient(clients.lit, GateKind.LitV3),
    gateKind: GateKind.LitV3,
    conditionalRecipientIndex: 0,
    stanzaIndex: stanzaIndex++,
  });

  // 2. G3 — dcipher OR drand per PDA g3_choice (PLATFORM PRINCIPLE).
  const g3GateKind = g3Choice === "dcipher" ? GateKind.Dcipher : GateKind.Drand;
  const g3Client = g3Choice === "dcipher" ? clients.dcipher : clients.drand;
  slots.push({
    client: requireClient(g3Client, g3GateKind),
    gateKind: g3GateKind,
    conditionalRecipientIndex: 0,
    stanzaIndex: stanzaIndex++,
  });

  // 3. G4 (top-level, always required).
  slots.push({
    client: requireClient(clients.g4, GateKind.G4),
    gateKind: GateKind.G4,
    conditionalRecipientIndex: 0,
    stanzaIndex: stanzaIndex++,
  });

  // 4. Conditional-recipient slots per profile.
  const conditionalCount = conditionalRecipientCount(profile);
  if (conditionalCount > 0) {
    const crClients = clients.conditionalRecipients ?? [];
    if (crClients.length < conditionalCount) {
      throw new SigmaGatherError(
        "GATE_CLIENT_MISSING",
        `profile requires ${conditionalCount} conditional-recipient gate client(s), got ${crClients.length}`,
        GateKind.ConditionalRecipient,
      );
    }
    for (let i = 0; i < conditionalCount; i++) {
      slots.push({
        client: requireClient(crClients[i], GateKind.ConditionalRecipient),
        gateKind: GateKind.ConditionalRecipient,
        conditionalRecipientIndex: i,
        stanzaIndex: stanzaIndex++,
      });
    }
  }

  return slots;
}

/**
 * Production `SigmaGatherer`. Holds the injected gate clients + a per-auth
 * context resolver. `gatherSigmas` runs the request→verify→assemble pipeline
 * for one authorization.
 */
export class ProductionSigmaGatherer implements SigmaGatherer {
  private readonly clients: SigmaGatherClients;
  private readonly resolveContext: (
    request: SigmaGatheringRequest,
  ) => Promise<SigmaGatherContext> | SigmaGatherContext;

  constructor(deps: {
    readonly clients: SigmaGatherClients;
    /**
     * Resolves the on-chain context (authorization block, recipient pubkeys,
     * profile, …) for an authorization. In production this reads live from the
     * chain at the authorization block (no cache — C3a); in tests it returns a
     * fixture.
     */
    readonly resolveContext: (
      request: SigmaGatheringRequest,
    ) => Promise<SigmaGatherContext> | SigmaGatherContext;
  }) {
    this.clients = deps.clients;
    this.resolveContext = deps.resolveContext;
  }

  async gatherSigmas(request: SigmaGatheringRequest): Promise<SigmaEvidenceBundle> {
    const context = await this.resolveContext(request);
    const sequence = buildRequiredSequence(this.clients, request.g3_choice, context.profile);

    const evidence: SigmaEvidence[] = [];
    for (const slot of sequence) {
      // Sequential, not Promise.all: the canonical Lit→G3→G4→conditional order
      // is the combiner's contract; building the array in-order guarantees it.
      evidence.push(await this.gatherOne(request, context, slot));
    }

    return {
      authorizationId: request.authorizationId,
      hCommit: request.h_commit,
      authorizationBlock: context.authorizationBlock,
      commitBlock: context.commitBlock,
      evidence,
    };
  }

  /**
   * Request σ from one gate, run a REAL verifySigma against it, and assemble the
   * `SigmaEvidence`. `metadata.verified` is bound to the actual verify result —
   * the F4 closure. Fail-closed on any error.
   */
  private async gatherOne(
    request: SigmaGatheringRequest,
    context: SigmaGatherContext,
    slot: RequiredGateSlot,
  ): Promise<SigmaEvidence> {
    const key = pubkeyKey(slot.gateKind, slot.conditionalRecipientIndex);

    const gateRecipientPubkey = context.gateRecipientPubkeys.get(key);
    if (gateRecipientPubkey === undefined) {
      throw new SigmaGatherError(
        "GATE_RECIPIENT_PUBKEY_ABSENT",
        `no gate-recipient pubkey for ${gateLabel(slot.gateKind)}[${slot.conditionalRecipientIndex}] at authorization block`,
        slot.gateKind,
      );
    }

    const requestInput: RequestSigmaInput<unknown> = {
      authorizationId: request.authorizationId,
      hCommit: request.h_commit,
      authorizationBlock: context.authorizationBlock,
      blockHash: context.blockHash,
      extras: context.gateExtras?.get(key),
    };

    // 1. Request σ once. Client errors fail-closed (no retry-as-success).
    let signed: RequestSigmaResult & { sigma: Uint8Array };
    try {
      signed = await slot.client.requestSigma(requestInput);
    } catch (error) {
      throw new SigmaGatherError(
        "GATE_REQUEST_FAILED",
        `${gateLabel(slot.gateKind)} requestSigma failed: ${errorMessage(error)}`,
        slot.gateKind,
      );
    }

    // 2. REAL verification — this closes the F4 seam. The verified flag below is
    //    NOT a trusted label; it is the literal output of verifySigma. A failed
    //    verify rejects the gate (fail-closed); it is never demoted to a stamped
    //    "true".
    let verifyResult: VerifySigmaResult;
    try {
      verifyResult = await slot.client.verifySigma({ ...requestInput, sigma: signed.sigma });
    } catch (error) {
      throw new SigmaGatherError(
        "GATE_VERIFY_THREW",
        `${gateLabel(slot.gateKind)} verifySigma threw: ${errorMessage(error)}`,
        slot.gateKind,
      );
    }

    if (!verifyResult.ok) {
      throw new SigmaGatherError(
        verifyResult.code || "GATE_VERIFY_FAILED",
        `${gateLabel(slot.gateKind)} σ verification failed${verifyResult.detail ? `: ${verifyResult.detail}` : ""}`,
        slot.gateKind,
      );
    }

    // 3. Assemble evidence in canonical position with the verified flag set from
    //    actual verification + the authoritative stanzaIndex. Gate-supplied
    //    metadata (share material, drand round, Lit assignment id, …) is
    //    threaded through; the gatherer overrides only the security-load-bearing
    //    fields it is authoritative for (`verified`, `verifyCode`, `stanzaIndex`)
    //    so a misbehaving client cannot pre-set `verified` itself.
    const metadata: Record<string, string | number | bigint | Hex32> = {
      ...signed.metadata,
      verified: "true",
      verifyCode: "ok",
      stanzaIndex: slot.stanzaIndex,
    };

    return {
      gateKind: slot.gateKind,
      conditionalRecipientIndex: slot.conditionalRecipientIndex,
      sigmaBytes: signed.sigma,
      gateRecipientPubkey,
      metadata,
    };
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Convenience factory mirroring the `create*Adapter` idiom in `@cealis/v3-custody`.
 */
export function createProductionSigmaGatherer(deps: {
  readonly clients: SigmaGatherClients;
  readonly resolveContext: (
    request: SigmaGatheringRequest,
  ) => Promise<SigmaGatherContext> | SigmaGatherContext;
}): SigmaGatherer {
  return new ProductionSigmaGatherer(deps);
}
