import type {
  CombinerExecutionContext,
  CombinerManifest,
  G3Choice,
  G4Phase,
  RecipientControlRequirement,
} from "../types/combiner-manifest.js";
import type { OperationalClass } from "../types/tier-behavior.js";
import { TIER_BEHAVIOR_MATRIX } from "../types/tier-behavior.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";
import {
  assertManifestContainsNoShareMaterial,
  sanitizeManifestValue,
} from "./sanitize.js";

export interface BuildCombinerManifestInput {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly authorization_block: number;
  readonly block_hash: Hex32;
  readonly pda_id: string;
  readonly g3_choice: G3Choice;
  readonly g4_phase: G4Phase;
  readonly operational_class: OperationalClass;
  readonly gate_endpoints: Record<string, unknown>;
  readonly registry_snapshot_refs: Record<string, unknown>;
  readonly recipient_policy: Record<string, unknown>;
  readonly combiner_execution_context?: CombinerExecutionContext;
  readonly delegation_allowed?: boolean;
  readonly recipient_control_requirement?: RecipientControlRequirement;
  readonly tee_hsm_required?: boolean;
  readonly risk_statement_required?: boolean;
  readonly policy_evidence_refs?: CombinerManifest["policy_evidence_refs"];
}

export function buildCombinerManifest(input: BuildCombinerManifestInput): CombinerManifest {
  const context = input.combiner_execution_context ?? contextForOperationalClass(input.operational_class);
  const manifest: CombinerManifest = {
    authorizationId: input.authorizationId,
    h_commit: input.h_commit,
    authorization_block: input.authorization_block,
    block_hash: input.block_hash,
    pda_id: input.pda_id,
    g3_choice: input.g3_choice,
    g4_phase: input.g4_phase,
    gate_endpoints: sanitizeRecord(input.gate_endpoints),
    registry_snapshot_refs: sanitizeRecord(input.registry_snapshot_refs),
    recipient_policy: sanitizeRecord(input.recipient_policy),
    combiner_execution_context: context,
    delegation_allowed: input.delegation_allowed ?? context === "delegated_non_custodial_service",
    recipient_control_requirement:
      input.recipient_control_requirement ?? recipientControlForOperationalClass(input.operational_class),
    tee_hsm_required:
      input.tee_hsm_required ??
      (input.operational_class === "regulated" || input.operational_class === "legal_effect"),
    risk_statement_required:
      input.risk_statement_required ?? input.operational_class === "consumer",
    policy_evidence_refs: input.policy_evidence_refs ?? [
      {
        ref_type: "combiner_context",
        digest: placeholderDigest("combiner_context"),
      },
    ],
  };
  assertManifestContainsNoShareMaterial(manifest);
  return manifest;
}

function sanitizeRecord(input: Record<string, unknown>): Record<string, unknown> {
  const sanitized = sanitizeManifestValue(input);
  if (sanitized === null || typeof sanitized !== "object" || Array.isArray(sanitized)) return {};
  return sanitized as Record<string, unknown>;
}

function contextForOperationalClass(operationalClass: OperationalClass): CombinerExecutionContext {
  const rule = TIER_BEHAVIOR_MATRIX.combiner_context[operationalClass];
  if (rule.includes("TEE/HSM")) return "recipient_controlled_tee";
  if (rule.includes("recipient-controlled")) return "recipient_controlled_tee";
  if (rule.includes("delegated") || rule.includes("recipient server")) {
    return "delegated_non_custodial_service";
  }
  return "audited_process_memory";
}

function recipientControlForOperationalClass(
  operationalClass: OperationalClass,
): RecipientControlRequirement {
  switch (operationalClass) {
    case "consumer":
      return "recipient_local";
    case "b2b_partner":
      return "delegated_allowed";
    case "regulated":
      return "recipient_controlled_service";
    case "legal_effect":
      return "delegation_prohibited";
  }
}

function placeholderDigest(label: string): Hex32 {
  const hex = Buffer.from(label, "utf8").toString("hex").padEnd(64, "0").slice(0, 64);
  return `0x${hex}` as Hex32;
}
