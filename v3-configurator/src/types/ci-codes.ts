// S2-4 §4.3 — Stage 2 crypto-invariant catalog (CI-01..CI-20).
//
// Verbatim from spec §4.3 — every entry's `invariant` and
// `configurator_check` prose is copied directly from the spec table.
// Phase A locks the enum + the per-CI descriptor metadata. Phase B
// implements the actual check functions (`src/validate/crypto-invariant/ci-XX.ts`)
// using these descriptors as the spec-compliance anchor.
//
// Per §4.3: "Adding a new Stage-2 invariant requires sub-class 5
// governance and coordinated author-lock review. If the new invariant
// changes S2-1 byte layout or commit semantics, it also requires S2-1
// governance and likely `commit_version` coordination."
//
// Per §4.1: "Each invalid condition has one canonical rejection owner.
// Stage 2 owns protocol-impossible or cryptographically impossible
// values that are invalid independent of partner policy."
//
// The foundation test `tests/foundation/ci-catalog.test.ts` asserts
// `CI_CATALOG.length === 20` and that every CI code follows the
// `CI-XX` numbering convention contiguously.

export type CiCode =
  | "CI-01"
  | "CI-02"
  | "CI-03"
  | "CI-04"
  | "CI-05"
  | "CI-06"
  | "CI-07"
  | "CI-08"
  | "CI-09"
  | "CI-10"
  | "CI-11"
  | "CI-12"
  | "CI-13"
  | "CI-14"
  | "CI-15"
  | "CI-16"
  | "CI-17"
  | "CI-18"
  | "CI-19"
  | "CI-20";

export interface CiDescriptor {
  readonly id: CiCode;
  /** Invariant prose verbatim from §4.3 table column "Invariant". */
  readonly invariant: string;
  /** Configurator-check prose verbatim from §4.3 table column "Configurator check". */
  readonly configurator_check: string;
}

/**
 * The 20-entry Stage-2 CI catalog.
 *
 * Prose is byte-exact verbatim from S2-4 §4.3 (lines 382-401). Any drift
 * here would silently desync Stage 2 enforcement from the spec — the
 * foundation test asserts catalog length 20 and the per-code Phase B
 * implementations cite these descriptors at the top of each file.
 */
export const CI_CATALOG: readonly CiDescriptor[] = [
  {
    id: "CI-01",
    invariant: "`commit_version = 0x0302` for new V2/V3-custody commits",
    configurator_check:
      "Reject any new PDA emission targeting another commit version unless an explicit versioned migration ceremony exists.",
  },
  {
    id: "CI-02",
    invariant: "σ-as-authorization, not σ-as-IKM",
    configurator_check:
      "Reject fields or templates that treat σ values as DEK material, HKDF IKM, stored secrets, or required confidential logs.",
  },
  {
    id: "CI-03",
    invariant: "A1+Shamir lifecycle",
    configurator_check:
      "Reject templates that wrap full DEK to any single gate instead of one Shamir share per stanza.",
  },
  {
    id: "CI-04",
    invariant: "Fixed base threshold is 3",
    configurator_check:
      "Reject PDA parameters that try to remove Lit, G3, or G4 from the fixed gate set for new partner-ready commits.",
  },
  {
    id: "CI-05",
    invariant: "Global threshold is `3 + k_conditional`",
    configurator_check:
      "Reject conditional-recipient policies whose threshold is not mapped to Shamir `k = 3 + k_conditional`.",
  },
  {
    id: "CI-06",
    invariant: "`1 <= k <= n` when `n > 0`; `k = 0` only when `n = 0`",
    configurator_check:
      "Reject impossible or degenerate conditional-recipient thresholds.",
  },
  {
    id: "CI-07",
    invariant: "Mode 3 RESERVED",
    configurator_check:
      "Reject `delivery_mode = WALLET_EIP1271` for active V2 PDAs.",
  },
  {
    id: "CI-08",
    invariant: "SD and escrow pipelines never cross",
    configurator_check:
      "Reject SD plans that read custody σ, require reveal-time plaintext, or cause SD failure to block escrow sealing.",
  },
  {
    id: "CI-09",
    invariant: "Mode B is incompatible with TEE-side SD",
    configurator_check:
      "Reject non-`escrow_only` SD mappings when ingestion mode is Mode B.",
  },
  {
    id: "CI-10",
    invariant: "`sdMerkleRoot` binding through S2-1 §4",
    configurator_check:
      "Reject SD-enabled PDA without a non-zero SD root plan; reject SD-off PDA that assigns non-`escrow_only` policy.",
  },
  {
    id: "CI-11",
    invariant: "No release path bypasses on-chain condition",
    configurator_check:
      "Reject templates with delivery, recipient, fallback, resolver, or override path that can produce plaintext before `RevealAuthorized` and gate-signing eligibility.",
  },
  {
    id: "CI-12",
    invariant: "Shred cannot bypass reveal gate-signing window",
    configurator_check:
      "Enforce mandatory `NOT post_challenge_reveal_in_progress` guardrail on every shred condition.",
  },
  {
    id: "CI-13",
    invariant: "`pda_root` uses S2-1 §3.3 29-field order",
    configurator_check:
      "Reject alternate pda_root preimage, missing field, optional field omission, or non-zero app-specific extra cryptographic field.",
  },
  {
    id: "CI-14",
    invariant: "`commit_AAD` uses S2-1 §4 22-field structure",
    configurator_check:
      "Reject alternate AAD field set or missing `sdMerkleRoot`.",
  },
  {
    id: "CI-15",
    invariant: "G4 phase semantics are fixed",
    configurator_check:
      "Reject unknown phase ids or templates that represent Phase 1 as a cryptographic non-custody or partner-ready guarantee. The per-PDA legal-effect/partner-ready mismatch is canonically rejected by CF-05 at Stage 4.",
  },
  {
    id: "CI-16",
    invariant: "Cross-vendor TEE disjointness is mandatory for Phase 2",
    configurator_check:
      "Reject configurations that preselect a Lit/G4 vendor-family pair known to be identical; mark ambiguous vendor family as fail-closed pending S2-6 classification.",
  },
  {
    id: "CI-17",
    invariant: "Gate-recipient pubkey lifecycle is fixed by gate kind",
    configurator_check:
      "Reject drand per-commit ephemeral expectation; reject Lit/G4/Conditional long-lived KEM mode where S2-3 requires per-commit ephemeral.",
  },
  {
    id: "CI-18",
    invariant: "Registry historical lookup discipline",
    configurator_check:
      "Reject templates requiring current-head registry substitution for historical commit verification.",
  },
  {
    id: "CI-19",
    invariant: "Reveal and shred axes are separated",
    configurator_check:
      "Reject a condition template where reveal terminal state implies shred terminal state or the reverse.",
  },
  {
    id: "CI-20",
    invariant: "DisclosureRegistry cannot authorize escrow reveal",
    configurator_check: "Reject SD proof success as any input to `RevealAuthorized`.",
  },
] as const;

/** Cross-spec invariant: catalog has exactly 20 entries. */
export const CI_CATALOG_COUNT = 20 as const;

/** Convenience: map CI code to descriptor. */
export const CI_BY_ID: ReadonlyMap<CiCode, CiDescriptor> = new Map(
  CI_CATALOG.map((desc): readonly [CiCode, CiDescriptor] => [desc.id, desc] as const),
);
