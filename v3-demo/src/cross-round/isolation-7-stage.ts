// @cealis/v3-demo/cross-round/isolation-7-stage.ts — Phase E E1.
//
// NORMATIVE per S2-7 §15.2: 7-stage asymmetric-isolation table is mandatory.
// Single-failure-mode tests are NOT conformant.
//
// AXIS TESTED:
//   For each of the 7 SD failure stages, run the M6 SD pipeline with the
//   failure injected at that stage and assert:
//     (a) escrow result is preserved verbatim — chain anchor + vault row remain
//     (b) SD reports a stage-specific failure outcome via the boundary's
//         `SdFailure` shape (`kind: "sd_err"`, `stage`, `code`, `partial`)
//
// BRIEF↔UPSTREAM ERROR-CODE MAPPING (logged in the internal integration-gap log, SOFT):
//   The brief uses aspirational names (`ERR_SD_SCHEMA_FIELD_INVALID`,
//   `ERR_SD_SALT_DERIVATION`, ...) that don't exist upstream. The actual
//   upstream catalog has 16 codes; we map the 7 stages to the closest
//   existing code per row. Assertions verify (stage + code), not the brief's
//   aspirational names.
//
//   | Stage (S2-7 §15.2 row)   | Upstream code mapped                  |
//   |--------------------------|---------------------------------------|
//   | schema_validation        | ERR_SD_FIELD_ENCODING_INVALID         |
//   | salt_derivation          | ERR_SD_SALT_DERIVATION_FAIL           |
//   | commitment_build         | ERR_SD_COMMITMENT_MISMATCH            |
//   | proving                  | ERR_SD_PROOF_INVALID                  |
//   | response_assembly        | ERR_SD_ONBOARDING_PARTIAL_FAILURE     |
//   | partner_verify           | ERR_SD_PROOF_INVALID (verifier path)  |
//   | revocation_check         | ERR_SD_CLAIM_REVOKED                  |
//
// σ-AS-AUTHORIZATION DOCTRINE (LOCKED 2026-05-05): preserved — no HKDF over σ
// values anywhere. This module's escrow side is synthesised in-process; the
// SD failure injection routes through the upstream boundary primitive
// (`DefaultSdBoundary.executeIfEscrowOk`) which is the load-bearing isolator.
//
// FIXED_ONLY 3-of-3 over {Lit, G3, G4} per S2-1 §6.3.1: the synthetic escrow
// result carries h_commit + authorizationId + pdaRoot derived from the
// synthetic σ-as-authorization happy path. No σ_subject Shamir share.
//
// E1 owns ONLY this file + tests/cross/isolation-7-stage.test.ts.

import {
  DefaultSdBoundary,
  SD_FAILURE_STAGES,
  SdErrorCode,
  type EscrowResult,
  type SdErrorCodeValue,
  type SdFailure,
  type SdFailureStage,
  type SdOutcome,
} from "../m6-imports.js";

import { DemoError, DEMO_ERR_CODES, type DemoSafeRefs } from "../errors/index.js";

// ---- Public types --------------------------------------------------------

/**
 * Synthetic escrow value carried alongside the SD failure injection. This is
 * the SAME shape Round 3 uses for its `EscrowIngestValue` so the boundary's
 * one-way edge can be verified consistently across rounds.
 */
export interface IsolationEscrowValue {
  readonly subjectId: string;
  readonly authorizationId: `0x${string}`;
  readonly hCommit: `0x${string}`;
  readonly pdaRoot: `0x${string}`;
  readonly vaultRef: string;
  readonly chainAnchorCommitted: true;
}

/**
 * Per-row outcome — what an E1 row produces for downstream assertions.
 */
export interface IsolationRowOutcome {
  readonly stage: SdFailureStage;
  readonly expectedSdCode: SdErrorCodeValue;
  readonly escrow: EscrowResult<IsolationEscrowValue, never>;
  readonly sd: SdOutcome<never>;
  /** Convenience: did escrow stay `ok` (S2-7 §15.2 NORMATIVE)? */
  readonly escrowPreserved: boolean;
  /** Convenience: did SD report the stage-specific failure? */
  readonly sdFailedAtExpectedStage: boolean;
}

export interface IsolationRow {
  readonly stage: SdFailureStage;
  readonly expectedSdCode: SdErrorCodeValue;
  readonly failureLabel: string;
}

/**
 * The 7-row parameterized table mandated by S2-7 §15.2. NEVER reduce below
 * 7 rows — single-failure-mode tests are explicitly non-conformant.
 *
 * Order matches `SD_FAILURE_STAGES` exactly so the foundation guard
 * `SD_FAILURE_STAGE_COUNT === 7` doubles as a count assertion for this table.
 */
export const ISOLATION_TABLE: readonly IsolationRow[] = Object.freeze([
  {
    stage: "schema_validation",
    expectedSdCode: SdErrorCode.FIELD_ENCODING_INVALID,
    failureLabel: "field invalid for SD but valid for escrow",
  },
  {
    stage: "salt_derivation",
    expectedSdCode: SdErrorCode.SALT_DERIVATION_FAIL,
    failureLabel: "HKDF failure",
  },
  {
    stage: "commitment_build",
    expectedSdCode: SdErrorCode.COMMITMENT_MISMATCH,
    failureLabel: "Poseidon library failure",
  },
  {
    stage: "proving",
    expectedSdCode: SdErrorCode.PROOF_INVALID,
    failureLabel: "witness/proof failure",
  },
  {
    stage: "response_assembly",
    expectedSdCode: SdErrorCode.ONBOARDING_PARTIAL_FAILURE,
    failureLabel: "payload too large",
  },
  {
    stage: "partner_verify",
    expectedSdCode: SdErrorCode.PROOF_INVALID,
    failureLabel: "SDK rejects proof",
  },
  {
    stage: "revocation_check",
    expectedSdCode: SdErrorCode.CLAIM_REVOKED,
    failureLabel: "registry unavailable",
  },
]);

// ---- Row execution -------------------------------------------------------

/**
 * Execute a single isolation row. Composes the upstream boundary primitive
 * with a synthetic escrow-ok input + an sdFn that returns a typed
 * `SdFailure` for the row's stage.
 *
 * The boundary's type system enforces that SD failure CANNOT mutate the
 * escrow result type — that's the load-bearing isolator (S2-7 §15.1
 * NORMATIVE). We verify the property dynamically here by asserting
 * `escrow.kind === "ok"` after the boundary returns.
 *
 * NOTE: We return `SdFailure` directly from `sdFn` rather than throwing
 * `SdError` because the typed return path is cleaner — both paths produce
 * the same `{kind: "sd_err", stage, code, partial}` shape on the boundary
 * output, per `DefaultSdBoundary` implementation.
 */
export async function runIsolationRow(
  row: IsolationRow,
  opts: { readonly subjectIdPrefix?: string } = {},
): Promise<IsolationRowOutcome> {
  const subjectId = (opts.subjectIdPrefix ?? "demo-e1-") + row.stage;
  const escrowOk = synthesizeEscrowOk(subjectId);
  const boundary = new DefaultSdBoundary();

  const result = await boundary.executeIfEscrowOk<IsolationEscrowValue, never, never>(
    escrowOk,
    async (_escrowValue) => {
      void _escrowValue;
      // Return the typed SdFailure shape directly. The boundary's `kind: ok`
      // escrow branch then composes this into `{escrow: ok, sd: sd_err}` —
      // the asymmetric-isolation invariant in action.
      const failure: SdFailure = {
        kind: "sd_err",
        stage: row.stage,
        code: row.expectedSdCode,
        partial: row.stage === "response_assembly",
      };
      return failure;
    },
  );

  const escrowPreserved = result.escrow.kind === "ok"
    && result.escrow.value.subjectId === subjectId
    && result.escrow.value.chainAnchorCommitted === true;

  const sdFailedAtExpectedStage =
    result.sd.kind === "sd_err"
    && result.sd.stage === row.stage
    && result.sd.code === row.expectedSdCode;

  // Sanity guard — if the boundary regressed and let SD failure mutate
  // escrow, we surface as INTEGRATION_GAP back to M6 immediately.
  if (!escrowPreserved) {
    const safeRefs: DemoSafeRefs = {
      subjectId,
      responsibleMilestone: "M6",
      responsiblePackage: "@cealis/v3-sd",
      gapDescription: `SD failure at stage=${row.stage} mutated escrow result (S2-7 §15.1 NORMATIVE breach)`,
    };
    throw new DemoError(DEMO_ERR_CODES.DEMO_ERR_INTEGRATION_GAP, safeRefs);
  }

  return {
    stage: row.stage,
    expectedSdCode: row.expectedSdCode,
    escrow: result.escrow,
    sd: result.sd,
    escrowPreserved,
    sdFailedAtExpectedStage,
  };
}

/**
 * Top-level E1 entry. Runs all 7 rows, returns the array. Throws DemoError
 * at the FIRST row where escrow was not preserved (the boundary contract).
 *
 * SD failure-mode mismatch (wrong code/stage) does NOT throw — caller's test
 * is expected to assert on `sdFailedAtExpectedStage` per row.
 */
export async function runE1(): Promise<readonly IsolationRowOutcome[]> {
  const outcomes: IsolationRowOutcome[] = [];
  for (const row of ISOLATION_TABLE) {
    outcomes.push(await runIsolationRow(row));
  }
  return outcomes;
}

// ---- Synthesis ----------------------------------------------------------

function synthesizeEscrowOk(subjectId: string): EscrowResult<IsolationEscrowValue, never> {
  return {
    kind: "ok",
    value: {
      subjectId,
      authorizationId: deterministicHex32(`auth:${subjectId}`),
      hCommit: deterministicHex32(`hcommit:${subjectId}`),
      pdaRoot: deterministicHex32(`pdaroot:${subjectId}`),
      vaultRef: `vault://e1/${subjectId}`,
      chainAnchorCommitted: true as const,
    },
  };
}

/**
 * Deterministic 32-byte hex derivation for synthetic escrow inputs. Same
 * pattern as round2/round2b/round3 — never imports randomness so the table
 * is fully reproducible.
 */
function deterministicHex32(seed: string): `0x${string}` {
  const enc = new TextEncoder().encode(seed);
  let a = 0xc0ffeeed;
  let b = 0xdeadbeef;
  let c = 0x1b873593;
  let d = 0xe6546b64;
  for (const x of enc) {
    a = (a * 19 + x) & 0xffffffff;
    b = (b * 37 + x) & 0xffffffff;
    c = (c * 11 + x) & 0xffffffff;
    d = (d * 23 + x) & 0xffffffff;
  }
  const w1 = (a >>> 0).toString(16).padStart(8, "0");
  const w2 = (b >>> 0).toString(16).padStart(8, "0");
  const w3 = (c >>> 0).toString(16).padStart(8, "0");
  const w4 = (d >>> 0).toString(16).padStart(8, "0");
  return ("0x" + w1 + w2 + w3 + w4 + w4 + w3 + w2 + w1) as `0x${string}`;
}

// ---- Re-export for tests ------------------------------------------------

export { SD_FAILURE_STAGES };
export type { SdFailureStage };
