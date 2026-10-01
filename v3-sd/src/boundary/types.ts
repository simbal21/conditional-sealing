// Asymmetric isolation boundary type per §15 + §1.5 NORMATIVE.
//
// Phase A LOCKS the type signature; Phase B fills the body.
//
// Discipline: the type system enforces that SD failure CANNOT mutate the
// escrow result type. Phase B `boundary.ts` implements `executeIfEscrowOk`
// such that:
//   - if `escrowResult.kind === "ok"`, it calls `sdFn(escrowResult.value)`
//     and returns `{ escrow: ok, sd: T | SdFailure }`.
//   - if `escrowResult.kind === "err"`, it RETURNS the escrow err verbatim
//     with `sd: { kind: "skipped" }` and DOES NOT call `sdFn`.
//
// SD failure ALWAYS produces `SdFailure` shape, NEVER an escrow value.

import type { SdFailureStage } from "../types/failure-modes.js";
import type { SdErrorCodeValue } from "../errors/codes.js";

export interface EscrowOk<E> {
  readonly kind: "ok";
  readonly value: E;
}

export interface EscrowErr<F> {
  readonly kind: "err";
  readonly failure: F;
}

export type EscrowResult<E, F> = EscrowOk<E> | EscrowErr<F>;

export interface SdSuccess<S> {
  readonly kind: "sd_ok";
  readonly value: S;
}

export interface SdFailure {
  readonly kind: "sd_err";
  readonly stage: SdFailureStage;
  readonly code: SdErrorCodeValue;
  readonly partial: boolean;
}

export interface SdSkipped {
  readonly kind: "sd_skipped";
  readonly reason: "escrow_failed";
}

export type SdOutcome<S> = SdSuccess<S> | SdFailure | SdSkipped;

/**
 * `SdBoundary.executeIfEscrowOk` — the load-bearing isolator. Signature only;
 * Phase B fills body.
 *
 *   if escrow succeeded:    call sdFn, return { escrow: ok, sd: success | failure }
 *   if escrow failed:       skip sdFn, return { escrow: err, sd: skipped }
 *
 * Failure path NEVER mutates `escrow`. Type system enforces because `sd_err`
 * does not carry an escrow field.
 */
export interface SdBoundary {
  executeIfEscrowOk<E, F, S>(
    escrowResult: EscrowResult<E, F>,
    sdFn: (escrowValue: E) => Promise<SdSuccess<S> | SdFailure>,
  ): Promise<{ readonly escrow: EscrowResult<E, F>; readonly sd: SdOutcome<S> }>;
}
