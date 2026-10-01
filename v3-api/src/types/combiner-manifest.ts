// CombinerManifest — verbatim from S2-5 App. A (lines 1949-1968).
//
// LOCKED at Phase A. The manifest is returned by `GET /v1/reveals/{authId}/
// delivery-manifest` and "includes no plaintext, no Shamir share, no DEK,
// and no share-bearing gate response" per §3.1 line 451.
//
// 16 required top-level fields per App. A `required: [...]` list verbatim.

import type { Hex32 } from "./reveal-artifact-bundle.js";

export type G3Choice = "dcipher" | "drand";
export type G4Phase = 1 | 2;

export type CombinerExecutionContext =
  | "audited_process_memory"
  | "recipient_controlled_tee"
  | "recipient_controlled_hsm"
  | "delegated_non_custodial_service"
  | "prohibited";

export type RecipientControlRequirement =
  | "recipient_local"
  | "recipient_controlled_service"
  | "delegated_allowed"
  | "delegation_prohibited";

export interface PolicyEvidenceRef {
  ref_type: string;
  digest: Hex32;
  url?: string;
}

/**
 * 16 required fields per App. A — verbatim ordering preserved.
 */
export interface CombinerManifest {
  authorizationId: Hex32;
  h_commit: Hex32;
  authorization_block: number;
  block_hash: Hex32;
  pda_id: string;
  g3_choice: G3Choice;
  g4_phase: G4Phase;
  gate_endpoints: Record<string, unknown>;
  registry_snapshot_refs: Record<string, unknown>;
  recipient_policy: Record<string, unknown>;
  combiner_execution_context: CombinerExecutionContext;
  delegation_allowed: boolean;
  recipient_control_requirement: RecipientControlRequirement;
  tee_hsm_required: boolean;
  risk_statement_required: boolean;
  policy_evidence_refs: PolicyEvidenceRef[];
}

export const COMBINER_MANIFEST_REQUIRED_FIELDS = [
  "authorizationId",
  "h_commit",
  "authorization_block",
  "block_hash",
  "pda_id",
  "g3_choice",
  "g4_phase",
  "gate_endpoints",
  "registry_snapshot_refs",
  "recipient_policy",
  "combiner_execution_context",
  "delegation_allowed",
  "recipient_control_requirement",
  "tee_hsm_required",
  "risk_statement_required",
  "policy_evidence_refs",
] as const;

export type CombinerManifestRequiredField = (typeof COMBINER_MANIFEST_REQUIRED_FIELDS)[number];

export const COMBINER_MANIFEST_REQUIRED_FIELD_COUNT: number =
  COMBINER_MANIFEST_REQUIRED_FIELDS.length;
