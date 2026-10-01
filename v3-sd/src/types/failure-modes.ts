// §15.2 lines 1201-1209 — 7-row failure-mode table (NORMATIVE).
//
// Every row has `escrowEffect = none`. The asymmetric-isolation invariant
// (§1.5 + §15.1) is that SD failure NEVER blocks escrow commit.
//
// Phase A foundation test asserts: 7 entries, all escrowEffect === "none".
// Phase B integration test `asymmetric-isolation-7-stage.test.ts` consumes
// this catalog; Phase E re-uses it for cross-stage E2E.

export const SD_FAILURE_STAGES = Object.freeze([
  "schema_validation",
  "salt_derivation",
  "commitment_build",
  "proving",
  "response_assembly",
  "partner_verify",
  "revocation_check",
] as const);

export type SdFailureStage = typeof SD_FAILURE_STAGES[number];

export interface SdFailureRow {
  readonly stage: SdFailureStage;
  readonly failureLabel: string;
  /** NORMATIVE — every row is `"none"`. Foundation test enforces. */
  readonly escrowEffect: "none";
  readonly sdEffect: string;
}

/**
 * §15.2 verbatim 7-row table.
 *
 * | Stage | Failure | Escrow effect | SD effect |
 * |---|---|---|---|
 * | schema validation | field invalid for SD but valid for escrow | none | affected SD fields fail |
 * | salt derivation | HKDF failure | none | SD fails |
 * | commitment build | Poseidon library failure | none | SD fails |
 * | proving | witness/proof failure | none | Claim fails |
 * | response assembly | payload too large | none | SD partial/failed |
 * | partner verify | SDK rejects proof | none | partner rejects Claim |
 * | revocation check | registry unavailable | none | partner policy retry/offline grace |
 */
export const SD_FAILURE_TABLE: ReadonlyArray<SdFailureRow> = Object.freeze([
  {
    stage: "schema_validation",
    failureLabel: "field invalid for SD but valid for escrow",
    escrowEffect: "none",
    sdEffect: "affected SD fields fail",
  },
  {
    stage: "salt_derivation",
    failureLabel: "HKDF failure",
    escrowEffect: "none",
    sdEffect: "SD fails",
  },
  {
    stage: "commitment_build",
    failureLabel: "Poseidon library failure",
    escrowEffect: "none",
    sdEffect: "SD fails",
  },
  {
    stage: "proving",
    failureLabel: "witness/proof failure",
    escrowEffect: "none",
    sdEffect: "Claim fails",
  },
  {
    stage: "response_assembly",
    failureLabel: "payload too large",
    escrowEffect: "none",
    sdEffect: "SD partial/failed",
  },
  {
    stage: "partner_verify",
    failureLabel: "SDK rejects proof",
    escrowEffect: "none",
    sdEffect: "partner rejects Claim",
  },
  {
    stage: "revocation_check",
    failureLabel: "registry unavailable",
    escrowEffect: "none",
    sdEffect: "partner policy retry/offline grace",
  },
]);

export const SD_FAILURE_STAGE_COUNT = 7 as const;
