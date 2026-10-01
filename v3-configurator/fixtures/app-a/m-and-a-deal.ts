import { prepareSubmittedPda } from "../../src/pda/emit.js";
import { hashToHex32 } from "../../src/pda/pda-root.js";
import type { MAndADealScaffold } from "./m-and-a-deal.scaffold.js";

export const mAndADeal: MAndADealScaffold = {
  use_case: "m_and_a",
  archetype: "multi_party_commercial_escrow",
  template_id: hashToHex32("ma_deal_multiparty_closing_v2"),
  template_name: "ma_deal_multiparty_closing_v2",
  g3_choice: "dcipher",
  g4_phase: 2,
  trust_tier: "B",
  reveal_condition: {
    module: "MultiPartySignal",
    template_pick: hashToHex32("ma_deal_multiparty_closing"),
    parameter_values: { closing_board_resolution_required: true },
    k_of_n: {
      k: 2,
      n: 4,
      independent_operators: true,
      signer_roles: [
        "ACQUIRER_COUNSEL",
        "SELLER_COUNSEL",
        "BOARD_REPRESENTATIVE",
        "REGISTERED_ORACLE",
      ],
    },
  },
  shred_condition: {
    mode: "P",
    spec_hash: hashToHex32("ma_deal_multiparty_closing_v2:shred"),
    mandatory_guardrail_present: true,
  },
  conditional_recipients: {
    n: 2,
    k: 1,
    role_tags: ["ACQUIRER_COUNSEL"],
  },
  reveal_challenge_window_seconds: 1_209_600n,
  shred_challenge_window_seconds: 1_209_600n,
  applicable_jurisdiction: {
    shape: "scalar",
    scalar_code: "DE",
  },
  qes_subject_required: false,
  qtsp_provider_ref: `0x${"00".repeat(32)}`,
  pricing_tier: "pilot",
  pricing_amounts: {
    retainer: 5_000n,
    per_identity: 500n,
    per_obligation: 0n,
    per_reveal: 0n,
    percentage_basis_points: 100,
    cap: 25_000n,
    floor: 0n,
  },
  usage_quota: { per_period_seconds: 2_592_000n, max_ops: 100 },
  legal_effect_expected: false,
  cealis_class_wide_halt_opt_out: false,
  partner_id: "partner_ma",
};

export const mAndADealSubmittedPda = prepareSubmittedPda(mAndADeal as unknown as Record<string, unknown>);
