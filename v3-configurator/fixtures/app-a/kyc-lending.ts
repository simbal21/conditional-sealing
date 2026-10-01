import { prepareSubmittedPda } from "../../src/pda/emit.js";
import { hashToHex32 } from "../../src/pda/pda-root.js";
import type { KycLendingScaffold } from "./kyc-lending.scaffold.js";

export const kycLending: KycLendingScaffold = {
  use_case: "kyc-lending",
  archetype: "enforcement",
  template_id: hashToHex32("kyc_lending_payment_default_v2"),
  template_name: "kyc_lending_payment_default_v2",
  g3_choice: "dcipher",
  g4_phase: 2,
  trust_tier: "A",
  reveal_condition: {
    module: "PaymentObligation",
    template_pick: hashToHex32("PaymentObligationModule"),
    parameter_values: { default_after_seconds: 0 },
  },
  shred_condition: {
    mode: "P",
    spec_hash: hashToHex32("kyc_lending_payment_default_v2:shred"),
    mandatory_guardrail_present: true,
  },
  reveal_challenge_window_seconds: 0n,
  shred_challenge_window_seconds: 0n,
  legal_effect_expected: true,
  cealis_class_wide_halt_opt_out: false,
  sd_default: "escrow_only",
  sd_field_policies: {
    "subject.identifier": "escrow_only",
    "claims.defaulted": "escrow_only",
  },
  partner_id: "partner_kyc_lending",
  retention_seconds: 94_608_000n,
  minimum_shred_latency_seconds: 0n,
};

export const kycLendingSubmittedPda = prepareSubmittedPda(kycLending as unknown as Record<string, unknown>);
