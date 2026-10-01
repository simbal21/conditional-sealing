// @cealis/v3-demo/cross-round/mode-b-defense-in-depth.ts — Phase E E2.
//
// NORMATIVE per S2-7 §14.2: Mode B + SD = forbidden, BOTH at M5 (API)
// AND at M6 (SD module). Defense-in-depth is NOT redundant — the two
// rejections are at different layers and either can catch the misconfig.
//
// 3 CASES TESTED:
//   A. M5 path:        createModeAIngestion with mode="MODE_B" → 409 / HttpProblem
//                      code = "SCHEMA.MODE_B_RESERVED" (upstream behaviour).
//   B. M6 module path: assertModeBSdCompatible directly with MODE_B + sd_enabled
//                      → SdError with code = "ERR_SD_CONFIG_MODE_B_INCOMPATIBLE".
//   C. Bare Mode B:    M5 with mode="MODE_B" + sd_enabled=false → STILL rejected
//                      at M5 (Mode B is reserved at the live endpoint, not
//                      a stripped-SD path).
//
// BRIEF↔UPSTREAM DRIFT (logged in the internal integration-gap log, SOFT):
//   The brief mentions `ERR_API_MODE_B_RESERVED` + `ERR_SD_CONFIG_MODE_B_INCOMPATIBLE`
//   and expects 400-status responses. The upstream actuals are:
//     - M5 throws `HttpProblem` with code `SCHEMA.MODE_B_RESERVED`, HTTP 409.
//     - M6 throws `SdError` with code `ERR_SD_CONFIG_MODE_B_INCOMPATIBLE` (no HTTP).
//   We assert against upstream actual behaviour, not the brief's aspirational
//   API status codes.
//
// E2 owns ONLY this file + tests/cross/mode-b.test.ts.

import { randomUUID } from "node:crypto";

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

import { assertModeBSdCompatible, SdError } from "../m6-imports.js";

import { DemoError, DEMO_ERR_CODES } from "../errors/index.js";

const { jcsDigestHex32, payloadDigestHex32 } = HCommit;

// ---- Result shapes -------------------------------------------------------

export interface ModeBCaseOutcome {
  readonly caseId: "A" | "B" | "C";
  readonly caseLabel: string;
  readonly rejected: boolean;
  readonly errorCategory: "HttpProblem" | "SdError" | "none";
  readonly errorCode: string;
  readonly httpStatus?: number;
}

export interface ModeBDefenseInDepthOutcome {
  readonly caseA: ModeBCaseOutcome;
  readonly caseB: ModeBCaseOutcome;
  readonly caseC: ModeBCaseOutcome;
  readonly allThreeIndependentlyRejected: boolean;
}

// ---- Top-level entry -----------------------------------------------------

/**
 * Top-level E2 entry. Runs all 3 cases sequentially and returns an outcome
 * object the tests can assert on. NEVER short-circuits — every case runs
 * even if an earlier one regressed (the cross-round invariant is about
 * defense-in-depth, so all 3 layers must independently work).
 */
export async function runE2(): Promise<ModeBDefenseInDepthOutcome> {
  const caseA = await runCaseAM5Rejects();
  const caseB = runCaseBM6Rejects();
  const caseC = await runCaseCBareModeBRejects();
  return {
    caseA,
    caseB,
    caseC,
    allThreeIndependentlyRejected:
      caseA.rejected && caseB.rejected && caseC.rejected,
  };
}

// ---- Case A: M5 rejects MODE_B + sd_enabled=true -------------------------

/**
 * Exercises the M5 ingestion path with the forbidden combo. The route's
 * `assertModeAOnly` fires BEFORE pda inspection — so we don't even need a
 * configured PDA to surface the rejection.
 */
export async function runCaseAM5Rejects(): Promise<ModeBCaseOutcome> {
  const caseLabel = "M5 rejects MODE_B + sd_enabled=true via assertModeAOnly";
  const correlationId = `corr-e2-a-${randomUUID()}`;
  const inputs = buildIngestRequest({
    mode: "MODE_B",
    sd_enabled: true,
  });

  try {
    await createModeAIngestion(
      inputs.request,
      buildDependencies(inputs.pda),
      buildContext(correlationId),
    );
    return {
      caseId: "A",
      caseLabel,
      rejected: false,
      errorCategory: "none",
      errorCode: "",
    };
  } catch (err) {
    if (err instanceof HttpProblem) {
      return {
        caseId: "A",
        caseLabel,
        rejected: true,
        errorCategory: "HttpProblem",
        errorCode: err.body.code,
        httpStatus: err.body.status,
      };
    }
    // Any other error type is an unexpected surface drift.
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      responsibleMilestone: "M5",
      responsiblePackage: "@cealis/v3-api",
      gapDescription: `M5 case A: unexpected non-HttpProblem rejection (${typeOf(err)})`,
    });
  }
}

// ---- Case B: M6 module rejects independently -----------------------------

/**
 * Exercises the M6 defense-in-depth — `assertModeBSdCompatible` is the
 * M6-side guard that fires even if M5 didn't catch the misconfig (e.g. an
 * SD pipeline invoked outside the REST surface).
 *
 * S2-7 §14.2 line 1182 NORMATIVE: this check MUST fire independently.
 */
export function runCaseBM6Rejects(): ModeBCaseOutcome {
  const caseLabel = "M6 module rejects MODE_B + sd_enabled=true independently";
  const correlationId = `corr-e2-b-${randomUUID()}`;

  try {
    assertModeBSdCompatible({
      ingestion_mode: "MODE_B",
      sd_enabled: true,
      correlationId,
    });
    return {
      caseId: "B",
      caseLabel,
      rejected: false,
      errorCategory: "none",
      errorCode: "",
    };
  } catch (err) {
    if (err instanceof SdError) {
      return {
        caseId: "B",
        caseLabel,
        rejected: true,
        errorCategory: "SdError",
        errorCode: err.code,
      };
    }
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      responsibleMilestone: "M6",
      responsiblePackage: "@cealis/v3-sd",
      gapDescription: `M6 case B: unexpected non-SdError rejection (${typeOf(err)})`,
    });
  }
}

// ---- Case C: bare Mode B (no SD) is STILL rejected at M5 -----------------

/**
 * The live Mode A endpoint rejects Mode B requests regardless of `sd_enabled`
 * — Mode B is reserved at this surface per memory project_m5_shipped_2026_05_11.md
 * and S2-5 §2.8.
 *
 * Distinguishing this case from Case A: sd_enabled is FALSE here. Case A
 * tests "Mode B + SD = forbidden"; Case C tests "Mode B is reserved at the
 * live endpoint regardless of SD".
 */
export async function runCaseCBareModeBRejects(): Promise<ModeBCaseOutcome> {
  const caseLabel = "M5 rejects bare MODE_B (sd_enabled=false) at the live endpoint";
  const correlationId = `corr-e2-c-${randomUUID()}`;
  const inputs = buildIngestRequest({
    mode: "MODE_B",
    sd_enabled: false,
  });

  try {
    await createModeAIngestion(
      inputs.request,
      buildDependencies(inputs.pda),
      buildContext(correlationId),
    );
    return {
      caseId: "C",
      caseLabel,
      rejected: false,
      errorCategory: "none",
      errorCode: "",
    };
  } catch (err) {
    if (err instanceof HttpProblem) {
      return {
        caseId: "C",
        caseLabel,
        rejected: true,
        errorCategory: "HttpProblem",
        errorCode: err.body.code,
        httpStatus: err.body.status,
      };
    }
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, {
      responsibleMilestone: "M5",
      responsiblePackage: "@cealis/v3-api",
      gapDescription: `M5 case C: unexpected non-HttpProblem rejection (${typeOf(err)})`,
    });
  }
}

// ---- Request synthesis ---------------------------------------------------

interface IngestRequestInputs {
  readonly request: ModeAIngestionRequest;
  readonly pda: PdaInspectionForIngest;
}

function buildIngestRequest(opts: {
  readonly mode: "MODE_A" | "MODE_B";
  readonly sd_enabled: boolean;
}): IngestRequestInputs {
  const pda = synthesizePda();
  const payload = { document: "E2 mode-b probe" };

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
    mode: opts.mode,
    sd_enabled: opts.sd_enabled,
  };
  return { request, pda };
}

function synthesizePda(): PdaInspectionForIngest {
  // E2 cases A/C exercise the Mode B rejection — assertModeAOnly fires
  // BEFORE pda inspection per the createModeAIngestion flow, so the PDA
  // config never reaches the G4 phase policy check. We still mirror
  // Round 1's testament fixture shape for safety (Phase 2 + b2b_partner)
  // so any future change to the rejection-ordering doesn't cascade-fail.
  return {
    pda_id: "demo-pda-e2",
    pda_version: "1",
    partner_id: "demo-partner-e2",
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

function buildContext(correlationId: string): CreateModeAContext {
  return {
    correlationId,
    idempotencyKey: `idem-${correlationId}`,
    apiVersion: "1.0-draft",
    clientAttestationDigestHeader: paddedHex(0),
    authKind: "partner_hmac",
  };
}

function buildDependencies(pda: PdaInspectionForIngest): IngestionDependencies {
  return {
    repository: new InMemoryIngestionRepository(),
    inspectPda: () => pda,
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

function typeOf(err: unknown): string {
  if (err === null) return "null";
  if (err === undefined) return "undefined";
  if (err instanceof Error) return err.name;
  return typeof err;
}

// Cast-discard for testing — `ModeAIngestionResponse` import is referenced
// only at the test/assertion layer; we keep the type re-export for shape.
void (null as unknown as ModeAIngestionResponse);
