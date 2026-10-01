// S2-4 §4.4 / §13.5 — Content-addressed template catalog (the "registered
// template set" Stage 3's template-id-active check validates against).
//
// WHY THIS EXISTS (security): pre-fix, `buildStage3Context` derived the active
// template set from the SUBMITTED PDA itself (`collectActiveTemplateIds`), so
// any content-addressed-looking template_id self-validated — a partner could
// reference an arbitrary 0x.. hash and Stage 3 would accept it. That is the
// no-op the TS-API-F-05 fix is meant to close at the template-pick surface.
//
// The principled minimal registry: the set of content-addressed template ids
// the shipping archetype scaffolds (`src/cli/init.ts`) reference. These are the
// known/available templates the PDA configurator ships with. A registered
// template_id validates; a non-registered (even well-formed content-addressed)
// id is REJECTED by `checkTemplateIdActive`.
//
// DESIGN NOTE: until a live PDA+ content-addressed template registry exists
// (S2-2 PluginHashRegistry / template catalog on-chain), this is the
// authoritative source of "active templates" for Stage 3. It is derived from
// the same template-name → hash construction the scaffolds use, so the catalog
// and the fixtures stay in lock-step by construction.

import { hashToHex32 } from "./pda-root.js";

/**
 * Template NAMES the shipping archetypes register, grouped by surface:
 *  - `top_level`: row 54 `template_id_pick` (PDA-level content-addressed template)
 *  - `condition`: row 56.1 `payment_obligation_template_pick` and the other
 *    per-module condition template picks (`reveal_condition.template_pick` /
 *    `evidence_template_pick`).
 *
 * These mirror `src/cli/init.ts` scaffoldFor(...) exactly. When a new shipping
 * archetype/template is added there, register its names here so its template_id
 * is recognized as active by Stage 3.
 */
const REGISTERED_TEMPLATE_NAMES: readonly string[] = [
  // row 54 — PDA-level template_id per shipping archetype.
  "kyc_lending_payment_default_v2",
  "testament_vital_records_k_of_n_v2",
  "evidence_provenance_retention_v2",
  "ma_deal_multiparty_closing_v2",
  "dead_man_switch_heartbeat_release_v2",
  // row 56.1 + sibling condition template picks per shipping archetype.
  "PaymentObligationModule",
  "vital_records_k_of_n",
  "evidence_oracle_attestation",
  "ma_deal_multiparty_closing",
  "heartbeat_release",
];

/**
 * The registered content-addressed template id set (0x-prefixed bytes32 hex),
 * derived from the registered template names via the same `hashToHex32`
 * construction the scaffolds use. This is the source of truth `Stage3` uses for
 * the active-template check — NOT the submitted PDA.
 */
export const REGISTERED_TEMPLATE_IDS: ReadonlySet<string> = new Set<string>(
  REGISTERED_TEMPLATE_NAMES.map((name) => hashToHex32(name).toLowerCase()),
);

/** Returns the registered (known/active) content-addressed template id set. */
export function registeredTemplateIds(): ReadonlySet<string> {
  return REGISTERED_TEMPLATE_IDS;
}
