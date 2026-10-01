// Foundation test — boundary type catalog smoke.
//
// Asserts type-level surface (Phase A signatures only). Phase B fills body.

import { describe, it, expectTypeOf } from "vitest";
import type {
  EscrowResult,
  EscrowOk,
  EscrowErr,
  SdSuccess,
  SdFailure,
  SdSkipped,
  SdOutcome,
  SdBoundary,
} from "../../src/boundary/types.js";

describe("§15 asymmetric isolation type surface", () => {
  it("EscrowOk + EscrowErr are discriminated", () => {
    const ok: EscrowOk<string> = { kind: "ok", value: "v" };
    const err: EscrowErr<string> = { kind: "err", failure: "boom" };
    expectTypeOf(ok.kind).toEqualTypeOf<"ok">();
    expectTypeOf(err.kind).toEqualTypeOf<"err">();
  });

  it("SdSuccess + SdFailure + SdSkipped are disjoint via discriminator", () => {
    expectTypeOf<SdSuccess<string>["kind"]>().toEqualTypeOf<"sd_ok">();
    expectTypeOf<SdFailure["kind"]>().toEqualTypeOf<"sd_err">();
    expectTypeOf<SdSkipped["kind"]>().toEqualTypeOf<"sd_skipped">();
  });

  it("EscrowResult union covers both ok and err", () => {
    expectTypeOf<EscrowResult<string, string>>().toEqualTypeOf<EscrowOk<string> | EscrowErr<string>>();
  });

  it("SdOutcome union covers all 3 cases", () => {
    expectTypeOf<SdOutcome<string>>().toEqualTypeOf<SdSuccess<string> | SdFailure | SdSkipped>();
  });

  it("SdBoundary exposes executeIfEscrowOk signature", () => {
    type Method = SdBoundary["executeIfEscrowOk"];
    expectTypeOf<Method>().not.toBeAny();
  });
});
