// PostgresPdaArtifactLoader (GAP-B) — the real configurator-artifact provenance
// seam for ingest. Reads the PDA CONFIG BODY (the configurator-emitted
// PartnerReadableInspection + the submitted PDA record + retention policy) from
// the content-addressed `pda_artifacts` table (migration 0010) and revives it to
// the runtime types the `PdaInspector` consumes.
//
// WHY A SEPARATE STORE: `partner_agreements` is a POINTER table (partner_id,
// pda_id, status, effective_at) — it does NOT carry the config body. The
// `PdaArtifactLoader` interface (pda-inspector.ts) is the swappable provenance
// concern; this is its Postgres impl. The artifact body is written by a
// configurator emit / provisioning step (`writePdaArtifact` below) and read back
// here. Content is immutable per (partner_id, pda_id, pda_version).
//
// SERIALIZATION: `PartnerReadableInspection` carries `Bytes32` (Uint8Array)
// fields + a `ReadonlyMap`, which are not JSON-native. The codec stores the
// inspection in a HEX-STRING form (the `Bytes32` fields as 0x-hex) and revives
// only the fields the inspector reads back into `Bytes32`. The `submitted` PDA
// record is plain JSON (the inspector's `deriveModuleSecurity` reads string /
// number / address fields only). This is a faithful round-trip of the consumed
// surface, not a synthesized default (platform principle: nothing hardcoded).
//
// V3 isolation (SECURITY.md): no @cealis/shared, no V1 packages, no
// V1 env vars. The injected `Sql` is read from the V3-scoped env at the
// composition root only.

import type { Sql } from "postgres";

import {
  bytesToHex,
  hexToBytes32,
  zeroBytes32,
  type PartnerReadableInspection,
} from "../m4-imports.js";
import type { Bytes32 } from "@cealis/v3-crypto";
import type { PdaArtifactLoader } from "./pda-inspector.js";

/** The JSON-safe artifact body persisted to `pda_artifacts.artifact_json`. Only
 *  the fields the inspector actually consumes are stored (the consumed surface of
 *  `PartnerReadableInspection` + the `submitted` record). */
export interface SerializedPdaArtifact {
  readonly inspection: SerializedInspection;
  readonly submitted: Record<string, unknown>;
  readonly retention_policy_id?: string;
  readonly halted?: boolean;
  readonly halt_reason?: string;
}

/** The consumed subset of `PartnerReadableInspection`, with `Bytes32` fields as
 *  0x-hex strings (JSON-safe). */
export interface SerializedInspection {
  readonly partner_id: string;
  readonly pda_id: string;
  readonly pda_version: string; // bigint → decimal string
  readonly pda_root: string;
  readonly schema_digest: string;
  readonly schema_summary_human_readable: string;
  readonly reveal_condition_summary: string;
  readonly shred_condition_summary: string;
  readonly trust_tier: "A" | "B" | "C";
  readonly g3_choice: "dcipher" | "drand";
  readonly g4_phase: 1 | 2;
  readonly conditional_recipient_policy_summary: {
    readonly n: number;
    readonly k: number;
    readonly role_summary: ReadonlyArray<string>;
    readonly updatable: boolean;
  };
  readonly retention_windows: {
    readonly retention_seconds: string; // bigint → decimal string
    readonly minimum_shred_latency_seconds: string;
  };
  readonly challenge_windows: {
    readonly reveal_seconds: string;
    readonly shred_seconds: string;
  };
  readonly shred_authority: "Subject" | "Joint" | "Operator" | "Timelock" | "Disabled";
  readonly shred_condition: {
    readonly mode: "P" | "F";
    readonly spec_digest: string;
    readonly mandatory_guardrail_present: true;
  };
  readonly legal_flags_art9_qes_jurisdiction: {
    readonly legal_effect_expected: boolean;
    readonly art_9_scoped: boolean;
    readonly art_9_basis_id: number;
    readonly qes_subject_required: boolean;
    readonly qtsp_provider_ref: string;
    readonly applicable_jurisdiction: string;
  };
}

/** Serialize a `PartnerReadableInspection` (consumed surface) to the JSON-safe
 *  hex form. Exported so a configurator emit / provisioning step can write it. */
export function serializeInspection(insp: PartnerReadableInspection): SerializedInspection {
  return {
    partner_id: bytesToHex(insp.partner_id),
    pda_id: bytesToHex(insp.pda_id),
    pda_version: insp.pda_version.toString(),
    pda_root: bytesToHex(insp.pda_root),
    schema_digest: bytesToHex(insp.schema_digest),
    schema_summary_human_readable: insp.schema_summary_human_readable,
    reveal_condition_summary: insp.reveal_condition_summary,
    shred_condition_summary: insp.shred_condition_summary,
    trust_tier: insp.trust_tier,
    g3_choice: insp.g3_choice,
    g4_phase: insp.g4_phase,
    conditional_recipient_policy_summary: {
      n: insp.conditional_recipient_policy_summary.n,
      k: insp.conditional_recipient_policy_summary.k,
      role_summary: [...insp.conditional_recipient_policy_summary.role_summary],
      updatable: insp.conditional_recipient_policy_summary.updatable,
    },
    retention_windows: {
      retention_seconds: insp.retention_windows.retention_seconds.toString(),
      minimum_shred_latency_seconds: insp.retention_windows.minimum_shred_latency_seconds.toString(),
    },
    challenge_windows: {
      reveal_seconds: insp.challenge_windows.reveal_seconds.toString(),
      shred_seconds: insp.challenge_windows.shred_seconds.toString(),
    },
    shred_authority: insp.shred_authority,
    shred_condition: {
      mode: insp.shred_condition.mode,
      spec_digest: bytesToHex(insp.shred_condition.spec_digest),
      mandatory_guardrail_present: true,
    },
    legal_flags_art9_qes_jurisdiction: {
      legal_effect_expected: insp.legal_flags_art9_qes_jurisdiction.legal_effect_expected,
      art_9_scoped: insp.legal_flags_art9_qes_jurisdiction.art_9_scoped,
      art_9_basis_id: insp.legal_flags_art9_qes_jurisdiction.art_9_basis_id,
      qes_subject_required: insp.legal_flags_art9_qes_jurisdiction.qes_subject_required,
      qtsp_provider_ref: bytesToHex(insp.legal_flags_art9_qes_jurisdiction.qtsp_provider_ref),
      applicable_jurisdiction: bytesToHex(insp.legal_flags_art9_qes_jurisdiction.applicable_jurisdiction),
    },
  };
}

/** Revive the JSON-safe form back to the runtime `PartnerReadableInspection`
 *  surface the inspector consumes. Fields the inspector never reads are filled
 *  with empty/zero structural placeholders (they are not on the consumed path —
 *  this is NOT a fabricated PDA value, just type-completion of unread fields). */
export function deserializeInspection(s: SerializedInspection): PartnerReadableInspection {
  const b = (hex: string): Bytes32 => hexToBytes32(hex as `0x${string}`) as Bytes32;
  return {
    partner_id: b(s.partner_id),
    pda_id: b(s.pda_id),
    pda_version: BigInt(s.pda_version),
    pda_root: b(s.pda_root),
    template_id: zeroBytes32() as Bytes32,
    template_digest: zeroBytes32() as Bytes32,
    schema_digest: b(s.schema_digest),
    schema_summary_human_readable: s.schema_summary_human_readable,
    reveal_condition_summary: s.reveal_condition_summary,
    shred_condition_summary: s.shred_condition_summary,
    trust_tier: s.trust_tier,
    oracle_refs: [],
    g3_choice: s.g3_choice,
    g4_phase: s.g4_phase,
    recipients_summary: [],
    conditional_recipient_policy_summary: {
      n: s.conditional_recipient_policy_summary.n,
      k: s.conditional_recipient_policy_summary.k,
      role_summary: s.conditional_recipient_policy_summary.role_summary,
      updatable: s.conditional_recipient_policy_summary.updatable,
    },
    sd_audit_diff_non_escrow_only: [],
    retention_windows: {
      retention_seconds: BigInt(s.retention_windows.retention_seconds),
      minimum_shred_latency_seconds: BigInt(s.retention_windows.minimum_shred_latency_seconds),
    },
    challenge_windows: {
      reveal_seconds: BigInt(s.challenge_windows.reveal_seconds),
      shred_seconds: BigInt(s.challenge_windows.shred_seconds),
    },
    shred_authority: s.shred_authority,
    shred_condition: {
      mode: s.shred_condition.mode,
      spec_digest: b(s.shred_condition.spec_digest),
      mandatory_guardrail_present: true,
    },
    legal_flags_art9_qes_jurisdiction: {
      legal_effect_expected: s.legal_flags_art9_qes_jurisdiction.legal_effect_expected,
      art_9_scoped: s.legal_flags_art9_qes_jurisdiction.art_9_scoped,
      art_9_basis_id: s.legal_flags_art9_qes_jurisdiction.art_9_basis_id,
      qes_subject_required: s.legal_flags_art9_qes_jurisdiction.qes_subject_required,
      qtsp_provider_ref: b(s.legal_flags_art9_qes_jurisdiction.qtsp_provider_ref),
      applicable_jurisdiction: b(s.legal_flags_art9_qes_jurisdiction.applicable_jurisdiction),
    },
    class_table_classification_per_surface: new Map(),
    defaults_applied_with_override_flags: [],
    validation_report_digest: zeroBytes32() as Bytes32,
    simulation_report_digest: zeroBytes32() as Bytes32,
    ipfs_cids: [],
    on_chain_tx_refs: [],
  };
}

/** Write a PDA artifact (configurator emit / provisioning step). Idempotent on
 *  (partner_id, pda_id, pda_version) — a re-write of the SAME triple overwrites
 *  the body (content-addressed; the body is immutable per version, so a re-write
 *  is the same bytes). */
export async function writePdaArtifact(
  sql: Sql,
  input: {
    readonly partner_id: string;
    readonly pda_id: string;
    readonly pda_version: string;
    readonly inspection: PartnerReadableInspection;
    readonly submitted: Record<string, unknown>;
    readonly retention_policy_id?: string;
    readonly halted?: boolean;
    readonly halt_reason?: string;
  },
): Promise<void> {
  const body: SerializedPdaArtifact = {
    inspection: serializeInspection(input.inspection),
    submitted: input.submitted,
    ...(input.retention_policy_id !== undefined ? { retention_policy_id: input.retention_policy_id } : {}),
    ...(input.halted !== undefined ? { halted: input.halted } : {}),
    ...(input.halt_reason !== undefined ? { halt_reason: input.halt_reason } : {}),
  };
  const artifactJson = JSON.stringify(body);
  await sql`
    INSERT INTO pda_artifacts (partner_id, pda_id, pda_version, artifact_json, retention_policy_id, halted, halt_reason)
    VALUES (
      ${input.partner_id}, ${input.pda_id}, ${input.pda_version},
      ${artifactJson}::jsonb, ${input.retention_policy_id ?? null},
      ${input.halted ?? null}, ${input.halt_reason ?? null}
    )
    ON CONFLICT (partner_id, pda_id, pda_version) DO UPDATE SET
      artifact_json = EXCLUDED.artifact_json,
      retention_policy_id = EXCLUDED.retention_policy_id,
      halted = EXCLUDED.halted,
      halt_reason = EXCLUDED.halt_reason
  `;
}

/** The real Postgres-backed `PdaArtifactLoader`. Reads the config body from
 *  `pda_artifacts` and revives it. Throws when no artifact exists for the
 *  (partner_id, pda_id, pda_version) — fail-loud, never a fabricated default. */
export class PostgresPdaArtifactLoader implements PdaArtifactLoader {
  constructor(private readonly sql: Sql) {}

  async load(input: {
    readonly partner_id: string;
    readonly pda_id: string;
    readonly pda_version: string;
  }): Promise<{
    readonly inspection: PartnerReadableInspection;
    readonly submitted: Record<string, unknown>;
    readonly retention_policy_id?: string;
    readonly halted?: boolean;
    readonly halt_reason?: string;
  }> {
    const rows = await this.sql<{
      artifact_json: SerializedPdaArtifact;
      retention_policy_id: string | null;
      halted: boolean | null;
      halt_reason: string | null;
    }[]>`
      SELECT artifact_json, retention_policy_id, halted, halt_reason
      FROM pda_artifacts
      WHERE partner_id = ${input.partner_id} AND pda_id = ${input.pda_id}
        AND pda_version = ${input.pda_version}
      LIMIT 1
    `;
    const row = rows[0];
    if (!row) {
      throw new Error(
        `PostgresPdaArtifactLoader: no pda_artifacts row for partner_id=${input.partner_id} ` +
          `pda_id=${input.pda_id} pda_version=${input.pda_version}. Write the configurator artifact ` +
          "(writePdaArtifact) before live ingest.",
      );
    }
    const body = row.artifact_json;
    return {
      inspection: deserializeInspection(body.inspection),
      submitted: body.submitted,
      ...(row.retention_policy_id !== null ? { retention_policy_id: row.retention_policy_id } : {}),
      ...(row.halted !== null ? { halted: row.halted } : {}),
      ...(row.halt_reason !== null ? { halt_reason: row.halt_reason } : {}),
    };
  }
}
