// @cealis/v3-demo/cross-round/halt-activation.ts — Phase E E3.
//
// NORMATIVE per S2-2 §14: pausing the V3 ConditionEngine blocks new
// ingestion attempts at M5.
//
// THREE-STEP CYCLE TESTED:
//   1. PauseActivationCeremony.run() → emits "PauseActivated".
//      Test-controlled closure flips `halted` to true on the inspectPda
//      callback that M5 consumes.
//   2. createModeAIngestion(...) → M5's `if (pda.halted === true)` branch
//      fires → HttpProblem with code = "GOVERNANCE.G4_REFUSED".
//   3. PauseDeactivationCeremony.run() → emits "PauseDeactivated".
//      Closure flips `halted` back to false. createModeAIngestion(...) now
//      succeeds (returns a 201-shape ModeAIngestionResponse).
//
// BRIEF↔UPSTREAM DRIFT (logged in the internal integration-gap log, SOFT):
//   Brief expects `ERR_API_HALT_ACTIVE` HTTP 503. Upstream M5 throws
//   `HttpProblem` with code = "GOVERNANCE.G4_REFUSED" HTTP 409 when
//   PdaInspectionForIngest.halted === true. We assert against upstream
//   actual behaviour, NOT brief aspirational shape.
//
// E3 owns ONLY this file + tests/cross/halt-activation.test.ts.

import { randomUUID } from "node:crypto";
import type { Address, Hex } from "viem";

import {
  createModeAIngestion,
  InMemoryIngestionRepository,
  type CreateModeAContext,
  type IngestionDependencies,
  type ModeAIngestionRequest,
  type ModeAIngestionResponse,
  type PdaInspectionForIngest,
  type VaultWriter,
} from "../m5-imports.js";
import {
  HttpProblem,
  buildSyntheticAttestationForRequest,
  HCommit,
  type ChainAnchorClient,
  type Hex32,
  type IngestionAnchorInput,
  type IngestionAnchorResult,
} from "@cealis/v3-api";

import {
  PauseActivationCeremony,
  PauseDeactivationCeremony,
  makeContext,
  generateCeremonyId,
  type CeremonyOutcome,
  type ChainClient as OpsChainClient,
} from "../m7-imports.js";
import { PauseAuthority } from "@cealis/v3-ops";

import { DemoError, DEMO_ERR_CODES } from "../errors/index.js";

const { jcsDigestHex32, payloadDigestHex32 } = HCommit;

// ---- Result shape --------------------------------------------------------

export interface HaltActivationOutcome {
  readonly step1PauseOutcome: CeremonyOutcome;
  readonly step1PauseActivatedEmitted: boolean;
  readonly step2Rejected: boolean;
  readonly step2ErrorCode: string;
  readonly step2HttpStatus?: number;
  readonly step3UnpauseOutcome: CeremonyOutcome;
  readonly step3PauseDeactivatedEmitted: boolean;
  readonly step4Succeeded: boolean;
  readonly step4Response?: ModeAIngestionResponse;
}

// ---- Top-level entry -----------------------------------------------------

/**
 * Top-level E3 entry. Drives the 4-step halt cycle:
 *   step 1: PauseActivationCeremony.run()                  → PauseActivated emitted
 *   step 2: createModeAIngestion()                          → REJECTED (halted=true)
 *   step 3: PauseDeactivationCeremony.run()                 → PauseDeactivated emitted
 *   step 4: createModeAIngestion() (same request shape)     → SUCCEEDS (halted=false)
 *
 * The mutable `halted` state is held in a closure that the inspectPda
 * dependency reads on every call — this is the cleanest in-process surface
 * for testing the M5 halt branch without a real chain client.
 */
export async function runE3(): Promise<HaltActivationOutcome> {
  // Closure state — flipped by the ceremonies' verify-stage hooks below.
  let halted = false;

  const pdaTemplate = synthesizePda();
  const inspectPda = (): PdaInspectionForIngest => ({
    ...pdaTemplate,
    halted,
  });

  const conditionEngineAddress =
    ("0x" + "ce".repeat(20)) as Address;
  const chain = makeInMemoryE3ChainClient();

  // ----- STEP 1: PauseActivationCeremony -----
  const pauseInput = {
    conditionEngineAddress,
    pauseAuthorityMode: PauseAuthority.PARTNER,
    pauseAuthorityId: paddedHex(0x21) as Hex,
    authorityProof: paddedHex(0x22) as Hex,
    hCommit: paddedHex(0x23) as Hex,
    reasonDigest: paddedHex(0x24) as Hex,
    durationSeconds: 3600, // 1h — well under §12.3 90-day cap
    addEntryCalldata: paddedHex(0x25) as Hex,
    salt: paddedHex(0x26) as Hex,
  };
  const pauseCeremony = new PauseActivationCeremony(pauseInput);
  const pauseContext = makeContext({
    ceremonyId: generateCeremonyId("pause-activation"),
    commitBlock: 0n,
    chainId: 31337,
    dryRun: true,
    slug: "pause-activation",
  });
  const step1PauseOutcome = await pauseCeremony.run({ context: pauseContext, chain });
  // ConditionEngine paused on-chain → flip the mock halted flag so
  // subsequent inspectPda() returns halted: true.
  halted = true;

  const step1PauseActivatedEmitted =
    step1PauseOutcome.emittedEvents.includes("PauseActivated");

  // ----- STEP 2: ingestion attempt while halted → expect rejection -----
  const correlationId2 = `corr-e3-2-${randomUUID()}`;
  const inputs2 = buildIngestRequest();
  let step2Rejected = false;
  let step2ErrorCode = "";
  let step2HttpStatus: number | undefined;

  try {
    await createModeAIngestion(
      inputs2.request,
      buildDependencies(inspectPda),
      buildContext(correlationId2, inputs2.request.client_attestation_digest),
    );
  } catch (err) {
    if (err instanceof HttpProblem) {
      step2Rejected = true;
      step2ErrorCode = err.body.code;
      step2HttpStatus = err.body.status;
    } else {
      throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
        responsibleMilestone: "M5",
        responsiblePackage: "@cealis/v3-api",
        gapDescription: `E3 step 2: unexpected non-HttpProblem rejection (${err === null ? "null" : err instanceof Error ? err.name : typeof err})`,
      });
    }
  }

  if (!step2Rejected) {
    // Halt didn't block — surface as INTEGRATION_GAP back to M5.
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      responsibleMilestone: "M5",
      responsiblePackage: "@cealis/v3-api",
      gapDescription: "E3 step 2: createModeAIngestion did NOT reject under halted=true (S2-2 §14 NORMATIVE breach)",
    });
  }

  // ----- STEP 3: PauseDeactivationCeremony -----
  const unpauseInput = {
    conditionEngineAddress,
    pauseAuthorityMode: PauseAuthority.PARTNER,
    pauseAuthorityId: paddedHex(0x21) as Hex,
    authorityProof: paddedHex(0x22) as Hex,
    hCommit: paddedHex(0x23) as Hex,
    unpauseReasonDigest: paddedHex(0x27) as Hex,
    addEntryCalldata: paddedHex(0x28) as Hex,
    salt: paddedHex(0x29) as Hex,
  };
  const unpauseCeremony = new PauseDeactivationCeremony(unpauseInput);
  const unpauseContext = makeContext({
    ceremonyId: generateCeremonyId("pause-deactivation"),
    commitBlock: 0n,
    chainId: 31337,
    dryRun: true,
    slug: "pause-deactivation",
  });
  const step3UnpauseOutcome = await unpauseCeremony.run({
    context: unpauseContext,
    chain,
  });
  // Unpause on-chain → flip the mock halted flag back.
  halted = false;

  const step3PauseDeactivatedEmitted =
    step3UnpauseOutcome.emittedEvents.includes("PauseDeactivated");

  // ----- STEP 4: ingestion attempt after unpause → expect success -----
  const correlationId4 = `corr-e3-4-${randomUUID()}`;
  const inputs4 = buildIngestRequest();
  let step4Succeeded = false;
  let step4Response: ModeAIngestionResponse | undefined;

  try {
    step4Response = await createModeAIngestion(
      inputs4.request,
      buildDependencies(inspectPda),
      buildContext(correlationId4, inputs4.request.client_attestation_digest),
    );
    step4Succeeded = true;
  } catch (err) {
    // Surface as INTEGRATION_GAP — post-unpause MUST succeed.
    const code = err instanceof HttpProblem ? err.body.code : "non-HttpProblem";
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      responsibleMilestone: "M5",
      responsiblePackage: "@cealis/v3-api",
      gapDescription: `E3 step 4: createModeAIngestion failed after unpause (code=${code})`,
    });
  }

  const result: HaltActivationOutcome = {
    step1PauseOutcome,
    step1PauseActivatedEmitted,
    step2Rejected,
    step2ErrorCode,
    ...(step2HttpStatus === undefined ? {} : { step2HttpStatus }),
    step3UnpauseOutcome,
    step3PauseDeactivatedEmitted,
    step4Succeeded,
    ...(step4Response === undefined ? {} : { step4Response }),
  };
  return result;
}

// ---- In-memory chain client for the pause ceremonies (dry-run) -----------

/**
 * Pause ceremonies in dry-run mode call `recordEvent("PauseActivated")`
 * or `recordEvent("PauseDeactivated")` themselves without needing the chain
 * to emit anything — so this in-memory chain is a no-op shell whose only
 * job is to satisfy the `ChainClient` interface contract. `readBlockNumber`
 * + `readBlockTimestamp` are the only methods actually called.
 */
function makeInMemoryE3ChainClient(): OpsChainClient {
  let block = 1_000_000n;
  let timestamp = 1_715_000_000n;
  let nonce = 0;

  function mintTxHash(label: string): Hex {
    nonce += 1;
    const buf = new TextEncoder().encode(`${label}-${nonce}-${block}-${timestamp}`);
    let acc = 0;
    for (const b of buf) acc = (acc * 33 + b) & 0xffffffff;
    const hex = (acc >>> 0).toString(16).padStart(8, "0");
    return ("0x" + hex.repeat(8)) as Hex;
  }

  return {
    async readBlockNumber() {
      block += 1n;
      return block;
    },
    async readBlockTimestamp() {
      timestamp += 1n;
      return timestamp;
    },
    async scheduleTimelock(args) {
      void args;
      nonce += 1;
      const hex = (nonce >>> 0).toString(16).padStart(8, "0");
      return {
        opId: ("0x" + hex.repeat(8)) as Hex,
        txHash: mintTxHash("schedule"),
        blockNumber: block,
      };
    },
    async executeTimelock(args) {
      void args;
      return {
        txHash: mintTxHash("execute"),
        blockNumber: block,
        events: [],
      };
    },
    async executeSafeMultisig(args) {
      void args;
      return {
        txHash: mintTxHash("safe"),
        blockNumber: block,
        events: [],
      };
    },
    async readDeprecationFlag(_args) {
      return null;
    },
    async cancelTimelock(_opId) {
      return { txHash: mintTxHash("cancel") };
    },
  };
}

// ---- Request synthesis (mirrors round1 / E2 shape) -----------------------

interface IngestRequestInputs {
  readonly request: ModeAIngestionRequest;
}

function buildIngestRequest(): IngestRequestInputs {
  const pda = synthesizePda();
  const payload = { document: "E3 halt probe" };

  const authorizationIdCandidate = paddedHex(1);
  const preflight_commit_context = {
    authorizationIdCandidate,
    pda_id: pda.pda_id,
    pda_version: pda.pda_version,
    partner_id: pda.partner_id,
    schema_digest: pda.schema_digest,
    payload_digest: payloadDigestHex32(payload, "jcs_json"),
    payload_canonicalization: "jcs_json" as const,
    pda_root: pda.pda_root,
    g3_choice: pda.g3_choice,
    g4_phase: pda.g4_phase,
    commit_block_number: 987_654,
    commit_block_hash: paddedHex(9),
  };
  const base = {
    pda_id: pda.pda_id,
    pda_version: pda.pda_version,
    partner_id: pda.partner_id,
    authorizationIdCandidate,
    preflight_commit_context,
    preflight_context_digest: jcsDigestHex32(preflight_commit_context),
    schema_digest: pda.schema_digest,
    payload_classification: { pii_class: "kyc", media_type: "application/json" },
    plaintext_payload: payload,
    client_attestation_digest: paddedHex(0),
  };
  const attestation = buildSyntheticAttestationForRequest(base);
  const request: ModeAIngestionRequest = {
    ...base,
    attestation_preflight: attestation.attestation_preflight,
    client_attestation_digest: attestation.attestation_preflight.digest,
  };
  return { request };
}

function synthesizePda(): Omit<PdaInspectionForIngest, "halted"> {
  // Mirror Round 1's testament fixture shape: Phase 2 + b2b_partner +
  // partner-HMAC + legal-effect-expected. The Phase-2 setting satisfies
  // `enforceG4PhasePolicy` (S2-5); the b2b_partner class admits the
  // partner_hmac auth path used at this seam (`assertAuthAllowed`).
  // E3's load-bearing assertion is the halt-gate, NOT the phase/auth
  // surface — so we pick the path of least friction.
  return {
    pda_id: "demo-pda-e3",
    pda_version: "1",
    partner_id: "demo-partner-e3",
    pda_root: paddedHex(99),
    schema_digest: paddedHex(2),
    g3_choice: "drand",
    g4_phase: 2,
    operational_class: "b2b_partner",
    trust_tier: "tier_b",
    retention_seconds: 94_608_000n,
    partner_ready: true,
    legal_effect_expected: true,
  };
}

function buildContext(
  correlationId: string,
  clientAttestationDigest: Hex32,
): CreateModeAContext {
  return {
    correlationId,
    idempotencyKey: `idem-${correlationId}`,
    apiVersion: "1.0-draft",
    clientAttestationDigestHeader: clientAttestationDigest,
    authKind: "partner_hmac",
  };
}

function buildDependencies(
  inspectPda: () => PdaInspectionForIngest,
): IngestionDependencies {
  return {
    repository: new InMemoryIngestionRepository(),
    inspectPda,
    chainAnchor: synthesizeChainAnchorClient(),
    vault: synthesizeVaultWriter(),
    now: () => new Date("2026-05-14T00:00:00.000Z"),
  };
}

function synthesizeChainAnchorClient(): ChainAnchorClient {
  return {
    async anchor(
      input: IngestionAnchorInput,
      attempt: number,
    ): Promise<IngestionAnchorResult> {
      return {
        commit_tx_hash: `0x${input.h_commit.slice(2)}`,
        commit_block: 12_345 + attempt,
        commit_block_hash: input.commit_block_hash,
        attempts: attempt,
      };
    },
  };
}

function synthesizeVaultWriter(): VaultWriter {
  return {
    async write(input: {
      readonly h_commit: Hex32;
      readonly plaintext: Uint8Array;
      readonly payload_classification: Record<string, unknown>;
    }): Promise<{ readonly vault_ref: string }> {
      void input.plaintext;
      void input.payload_classification;
      return { vault_ref: `vault://${input.h_commit}` };
    },
  };
}

function paddedHex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}
