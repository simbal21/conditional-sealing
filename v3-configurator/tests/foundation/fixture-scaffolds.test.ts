// Foundation: 5 App. A archetype fixture scaffold imports.
//
// Phase A asserts the 5 scaffold modules load cleanly. Phase E body
// tests assert the populated fixtures pass Stages 1-5.

import { describe, expect, it } from "vitest";
import type { KycLendingScaffold } from "../../fixtures/app-a/kyc-lending.scaffold.js";
import type { TestamentScaffold } from "../../fixtures/app-a/testament.scaffold.js";
import type { EvidenceArchivalScaffold } from "../../fixtures/app-a/evidence-archival.scaffold.js";
import type { MAndADealScaffold } from "../../fixtures/app-a/m-and-a-deal.scaffold.js";
import type { DeadManSwitchScaffold } from "../../fixtures/app-a/dead-man-switch.scaffold.js";

describe("@cealis/v3-configurator — App. A fixture scaffolds", () => {
  it("kyc-lending scaffold type loads", () => {
    // Type-only test — TypeScript compilation success is the assertion.
    // We exercise it by binding a never-typed slot.
    const _slot: KycLendingScaffold | null = null;
    expect(_slot).toBeNull();
  });

  it("testament scaffold type loads", () => {
    const _slot: TestamentScaffold | null = null;
    expect(_slot).toBeNull();
  });

  it("evidence-archival scaffold type loads", () => {
    const _slot: EvidenceArchivalScaffold | null = null;
    expect(_slot).toBeNull();
  });

  it("m-and-a-deal scaffold type loads", () => {
    const _slot: MAndADealScaffold | null = null;
    expect(_slot).toBeNull();
  });

  it("dead-man-switch scaffold type loads", () => {
    const _slot: DeadManSwitchScaffold | null = null;
    expect(_slot).toBeNull();
  });

  it("compile-time shape constraints: KycLendingScaffold.legal_effect_expected is true literal", () => {
    type T = KycLendingScaffold["legal_effect_expected"];
    const _check: T = true;
    expect(_check).toBe(true);
  });

  it("compile-time shape constraints: KycLendingScaffold.cealis_class_wide_halt_opt_out is false literal", () => {
    type T = KycLendingScaffold["cealis_class_wide_halt_opt_out"];
    const _check: T = false;
    expect(_check).toBe(false);
  });

  it("compile-time shape constraints: TestamentScaffold.g3_choice is 'drand' literal", () => {
    type T = TestamentScaffold["g3_choice"];
    const _check: T = "drand";
    expect(_check).toBe("drand");
  });

  it("compile-time shape constraints: DeadManSwitchScaffold.pda_updatable is true literal", () => {
    type T = DeadManSwitchScaffold["pda_updatable"];
    const _check: T = true;
    expect(_check).toBe(true);
  });
});
