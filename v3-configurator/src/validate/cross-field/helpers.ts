import {
  CF_BY_ID,
  type CfCode,
  type CfDescriptor,
} from "../../types/cf-codes.js";
import type {
  ConditionalRecipient,
  ConditionalRecipientPolicy,
  CrossFieldPda,
  MultiPartySignalConfig,
  OracleRef,
  TrustTier,
} from "./types.js";

export const FIVE_YEARS_SECONDS = 5n * 365n * 24n * 60n * 60n;

export function requiredCfDescriptor(
  descriptor: CfDescriptor | undefined,
  id: CfCode,
): CfDescriptor {
  if (descriptor === undefined) {
    throw new Error(`Missing CF descriptor ${id} in CF_BY_ID`);
  }
  return descriptor;
}

export function cfDescriptor(id: CfCode): CfDescriptor {
  return requiredCfDescriptor(CF_BY_ID.get(id), id);
}

export function toSeconds(value: bigint | number | undefined): bigint | null {
  if (value === undefined) return null;
  if (typeof value === "bigint") return value;
  if (!Number.isFinite(value)) return null;
  return BigInt(Math.trunc(value));
}

export function revealChallengeWindow(pda: CrossFieldPda): bigint {
  return (
    toSeconds(
      pda.reveal_challenge_window_seconds ?? pda.challenge_window_seconds,
    ) ?? 0n
  );
}

export function archetypeFloor(pda: CrossFieldPda): bigint {
  return toSeconds(pda.archetype_floor_seconds) ?? 0n;
}

export function minimumShredLatency(pda: CrossFieldPda): bigint {
  return (
    toSeconds(pda.minimum_shred_latency_seconds ?? pda.minimum_shred_latency) ??
    0n
  );
}

export function fireTimeTtl(pda: CrossFieldPda): bigint {
  return (
    toSeconds(
      pda.fire_time_ttl_estimate_seconds ?? pda.fire_time_ttl_estimate,
    ) ?? 0n
  );
}

export function getTrustTier(pda: CrossFieldPda): TrustTier {
  return pda.trust_tier ?? "A";
}

export function getRelevantRevealTiers(
  pda: CrossFieldPda,
): readonly TrustTier[] {
  const tiers: TrustTier[] = [];
  if (pda.relevant_reveal_condition_tiers !== undefined)
    tiers.push(...pda.relevant_reveal_condition_tiers);
  if (pda.reveal_condition?.tier !== undefined)
    tiers.push(pda.reveal_condition.tier);
  for (const ref of pda.oracle_refs ?? []) {
    if (ref.axis === undefined || ref.axis === "reveal" || ref.axis === "both")
      tiers.push(ref.tier);
  }
  if (tiers.length === 0) tiers.push(getTrustTier(pda));
  return tiers;
}

export function hasTierBorCRelevantReveal(pda: CrossFieldPda): boolean {
  return getRelevantRevealTiers(pda).some(
    (tier) => tier === "B" || tier === "C",
  );
}

export function eligibleChallengersContainSubject(pda: CrossFieldPda): boolean {
  const challengers = pda.eligible_challengers_reveal ?? [];
  const subjectId = pda.subject_id;
  return (
    challengers.includes("subject") ||
    challengers.includes("SUBJECT") ||
    (subjectId !== undefined && challengers.includes(subjectId))
  );
}

export function conditionalRecipientPolicy(
  pda: CrossFieldPda,
): ConditionalRecipientPolicy | null {
  return pda.conditional_recipient_policy ?? pda.conditional_recipients ?? null;
}

export function allConditionalRecipients(
  pda: CrossFieldPda,
): readonly ConditionalRecipient[] {
  const policyRecipients = conditionalRecipientPolicy(pda)?.recipients ?? [];
  return [...policyRecipients, ...(pda.recipients ?? [])];
}

export function isPhase2(phase: CrossFieldPda["g4_phase"]): boolean {
  return phase === 2 || phase === "Phase 2";
}

export function getOracleRefs(pda: CrossFieldPda): readonly OracleRef[] {
  const mpsRefs = getMultiPartySignal(pda)?.oracle_refs ?? [];
  return [...(pda.oracle_refs ?? []), ...mpsRefs];
}

export function getMultiPartySignal(
  pda: CrossFieldPda,
): MultiPartySignalConfig | null {
  return pda.multi_party_signal ?? pda.reveal_condition?.k_of_n ?? null;
}

export function stableUniqueCount(values: readonly string[]): number {
  return new Set(values).size;
}

export function archetypeKey(pda: CrossFieldPda): string {
  return (pda.archetype ?? pda.use_case ?? "")
    .toLowerCase()
    .replaceAll("-", "_");
}

export function hasAcknowledgment(pda: CrossFieldPda, ack: string): boolean {
  if (
    pda.partner_mps_opt_out_ack_bound === true &&
    ack === "multi_oracle_opt_out"
  )
    return true;
  if (
    pda.tier_c_acknowledgment_bound === true &&
    ack === "tier_c_trust_acknowledgment"
  )
    return true;
  const acknowledgments = [
    ...(pda.inspection_surface?.partner_acknowledgments ?? []),
    ...(pda.inspection_surface?.bound_acknowledgments ?? []),
  ];
  return acknowledgments.includes(ack);
}
