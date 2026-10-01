// @cealis/v3-demo/m4-imports — typed re-export facade for
// @cealis/v3-configurator/fixtures.
//
// 5 ARCHETYPE FIXTURES. The brief uses PascalCase ("TestamentPDA",
// "DeadManSwitchPDA"); upstream names them camelCase. Mapping:
//
//   Brief                | Upstream symbol              | Used by
//   ---------------------|------------------------------|------------------
//   TestamentPDA         | testament / testamentSubmittedPda           | Round 1 + Round 3
//   DeadManSwitchPDA     | deadManSwitch / deadManSwitchSubmittedPda   | Round 2 + Round 2b
//   KycLendingPDA        | kycLending / kycLendingSubmittedPda         | reserved
//   EvidenceArchivalPDA  | evidenceArchival / evidenceArchivalSubmittedPda | reserved
//   MAndADealPDA         | mAndADeal / mAndADealSubmittedPda           | reserved
//
// `*SubmittedPda` is the submitted-form PDA payload (post-`emit`); raw
// `<archetype>` is the pre-submission spec object.
//
// Each fixture is consumed by round code via `setup.ts.loadPdaFixture(name)`.

export {
  kycLending,
  kycLendingSubmittedPda,
  testament,
  testamentSubmittedPda,
  evidenceArchival,
  evidenceArchivalSubmittedPda,
  mAndADeal,
  mAndADealSubmittedPda,
  deadManSwitch,
  deadManSwitchSubmittedPda,
  APP_A_FIXTURES,
} from "@cealis/v3-configurator/fixtures";

/**
 * Round-keyed fixture map. Round code resolves its fixture via this map
 * rather than touching the upstream symbol names directly — keeps the brief
 * vocabulary (rounds) one indirection away from upstream vocabulary
 * (fixtures).
 */
export const M8_ROUND_FIXTURES = {
  round1: "testament",
  round2: "deadManSwitch",
  round2b: "testament", // distinct subject; same archetype as round 1
  round3: "testament",
} as const;

export type M8RoundKey = keyof typeof M8_ROUND_FIXTURES;
