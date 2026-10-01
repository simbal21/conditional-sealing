import type { DefaultRecord } from "./use-case-index.js";
import { normalizeDefaultKey } from "./use-case-index.js";

export type ArchetypeKey =
  | "enforcement"
  | "kyc_lending_chain_native"
  | "kyc_lending_oracle_attested"
  | "evidence"
  | "tamper_proof_retention"
  | "testament"
  | "irreversible_personal_reveal"
  | "archival"
  | "dead_man_switch"
  | "conditional_reveal_liveness"
  | "multi_party_commercial_escrow";

export const ARCHETYPE_DEFAULTS: Readonly<Record<ArchetypeKey, DefaultRecord>> =
  {
    enforcement: {
      trust_tier: "A",
      reveal_challenge_window_seconds: 0,
      shred_challenge_window_seconds: 0,
      resolver_type: "chain_native",
      sd_default: "escrow_only",
      authenticator_class: "platform_authenticator",
    },
    kyc_lending_chain_native: {
      trust_tier: "A",
      reveal_challenge_window_seconds: 0,
      shred_challenge_window_seconds: 0,
    },
    kyc_lending_oracle_attested: {
      trust_tier: "B",
      reveal_challenge_window_seconds: 1209600,
      shred_challenge_window_seconds: 1209600,
      resolver_type: "human_endpoint",
    },
    evidence: {
      trust_tier: "B",
      reveal_challenge_window_seconds: 604800,
      shred_challenge_window_seconds: 604800,
      shred_authority: "Joint",
    },
    tamper_proof_retention: {
      trust_tier: "B",
      reveal_challenge_window_seconds: 604800,
      shred_challenge_window_seconds: 604800,
      shred_authority: "Joint",
    },
    testament: {
      trust_tier: "B",
      reveal_challenge_window_seconds: 0,
      shred_challenge_window_seconds: 0,
      resolver_type: "human_endpoint",
    },
    irreversible_personal_reveal: {
      trust_tier: "B",
      reveal_challenge_window_seconds: 0,
      shred_challenge_window_seconds: 0,
    },
    archival: {
      trust_tier: "A",
      reveal_challenge_window_seconds: 0,
      shred_authority: "Disabled",
    },
    dead_man_switch: {
      trust_tier: "B",
      reveal_challenge_window_seconds: 0,
      shred_authority: "Subject",
    },
    conditional_reveal_liveness: {
      trust_tier: "B",
      reveal_challenge_window_seconds: 0,
      shred_authority: "Subject",
    },
    multi_party_commercial_escrow: {
      trust_tier: "B",
      reveal_challenge_window_seconds: 1209600,
      resolver_type: "human_endpoint",
    },
  } as const;

export function getArchetypeDefaults(
  archetype: string | undefined,
): DefaultRecord {
  if (archetype === undefined) return {};
  return (
    ARCHETYPE_DEFAULTS[normalizeDefaultKey(archetype) as ArchetypeKey] ?? {}
  );
}
