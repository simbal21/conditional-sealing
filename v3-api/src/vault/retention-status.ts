import { TIER_BEHAVIOR_MATRIX } from "../types/tier-behavior.js";

export interface RetentionStatus {
  readonly h_commit: string;
  readonly retention_policy_id: string;
  readonly retention_expires_at: string;
  readonly legal_basis_ref: string;
  readonly shred_authority: string;
  readonly shred_condition_summary: string;
  readonly vault_access_log_retention: string;
  readonly webhook_metadata_retention: string;
  readonly retention_floor_statement: string;
}

export function buildRetentionStatus(input: {
  readonly h_commit: string;
  readonly retention_expires_at?: string;
  readonly shred_authority?: string;
  readonly shred_condition_summary?: string;
}): RetentionStatus {
  return {
    h_commit: input.h_commit,
    retention_policy_id: "obligation_plus_3y",
    retention_expires_at: input.retention_expires_at ?? "2029-01-01T00:00:00.000Z",
    legal_basis_ref: "gdpr_art_6_1_b",
    shred_authority: input.shred_authority ?? "Subject",
    shred_condition_summary: input.shred_condition_summary ?? "PDA condition plus mandatory guardrail",
    vault_access_log_retention: "P12M",
    webhook_metadata_retention: "P90D",
    retention_floor_statement: TIER_BEHAVIOR_MATRIX.retention_floor.b2b_partner,
  };
}
