import type { SimulationHarnessResult } from "../simulation/index.js";
import {
  PARTNER_INSPECTION_PRIMITIVE_FIELDS,
  type PartnerReadableInspection,
} from "../types/partner-inspection.js";
import type { AppliedDefaultRecord } from "../defaults/precedence.js";
import type { ClassTableRow } from "../types/class-table.js";
import type { IpfsPin } from "./ipfs-pin.js";
import { bytesToHex, hashToBytes32, hexToBytes32 } from "./pda-root.js";
import type { MockPdaRegisteredEvent } from "./triple-root-guard.js";

export interface InspectionInput {
  readonly submitted: Record<string, unknown>;
  readonly pdaRoot: Uint8Array;
  readonly templateDigest: Uint8Array;
  readonly validationReportDigest: Uint8Array;
  readonly simulation: SimulationHarnessResult;
  readonly ipfsPins: readonly IpfsPin[];
  readonly event: MockPdaRegisteredEvent;
  readonly classTableRows: readonly ClassTableRow[];
  readonly defaults: readonly AppliedDefaultRecord[];
}

export function renderInspection(input: InspectionInput): PartnerReadableInspection {
  const submitted = input.submitted;
  const reveal = recordValue(submitted.reveal_condition);
  const shred = recordValue(submitted.shred_condition);
  const conditional = recordValue(submitted.conditional_recipients);
  const extension = recordValue(submitted.extension_metadata);
  const sdPolicies = recordValue(submitted.sd_field_policies);

  const inspection: PartnerReadableInspection = {
    partner_id: hashToBytes32(submitted.partner_id ?? "partner:unknown"),
    pda_id: hexToBytes32(String(submitted.pda_id)),
    pda_version: toBigInt(submitted.pda_version ?? 1),
    pda_root: input.pdaRoot,
    template_id: hexToBytes32(String(submitted.template_id)),
    template_digest: input.templateDigest,
    schema_digest: hashToBytes32(submitted.schema ?? {}),
    schema_summary_human_readable: schemaSummary(submitted.schema),
    reveal_condition_summary: `${String(reveal.module ?? "Condition")} ${String(reveal.mode ?? "P")}`,
    shred_condition_summary: `${String(shred.mode ?? "P")} with mandatory guardrail`,
    trust_tier: trustTier(submitted.trust_tier),
    oracle_refs: oracleRefs(reveal, submitted),
    g3_choice: submitted.g3_choice === "drand" ? "drand" : "dcipher",
    g4_phase: submitted.g4_phase === 1 ? 1 : 2,
    recipients_summary: recipientsSummary(submitted.recipients),
    conditional_recipient_policy_summary: {
      n: toNumber(conditional.n ?? 0),
      k: toNumber(conditional.k ?? 0),
      role_summary: arrayStrings(conditional.role_tags),
      updatable:
        conditional.updatable === true ||
        submitted.conditional_recipients_updatable === true ||
        extension.conditional_recipients_updatable === true,
    },
    sd_audit_diff_non_escrow_only: Object.entries(sdPolicies)
      .filter(([, value]) => value === "cleartext" || value === "zkp")
      .map(([field_path, value]) => ({
        field_path,
        sd_policy: value as "cleartext" | "zkp",
      })),
    retention_windows: {
      retention_seconds: toBigInt(submitted.retention_seconds ?? 0),
      minimum_shred_latency_seconds: toBigInt(submitted.minimum_shred_latency_seconds ?? 0),
    },
    challenge_windows: {
      reveal_seconds: toBigInt(submitted.reveal_challenge_window_seconds ?? 0),
      shred_seconds: toBigInt(submitted.shred_challenge_window_seconds ?? 0),
    },
    shred_authority: shredAuthority(extension.shred_authority),
    shred_condition: {
      mode: shred.mode === "F" ? "F" : "P",
      spec_digest: hexToBytes32(String(shred.spec_hash)),
      mandatory_guardrail_present: true,
    },
    legal_flags_art9_qes_jurisdiction: {
      legal_effect_expected: submitted.legal_effect_expected === true,
      art_9_scoped: extension.art_9_scoped === true,
      art_9_basis_id: toNumber(extension.art_9_basis_id ?? 0),
      qes_subject_required: extension.qes_subject_required === true,
      qtsp_provider_ref: hexOrHash(extension.qtsp_provider_ref ?? "qtsp:none"),
      applicable_jurisdiction: hashToBytes32(extension.applicable_jurisdiction ?? "jurisdiction:none"),
    },
    class_table_classification_per_surface: new Map(
      input.classTableRows.map((row) => [
        row.surface_name,
        {
          row_id: row.id,
          category: row.category,
          governance_sub_class: String(row.governance_sub_class),
        },
      ]),
    ),
    defaults_applied_with_override_flags: input.defaults.map((record) => ({
      field_path: record.field_path,
      default_value: String(record.default_value),
      applied_value: String(record.applied_value),
      overridden: record.overridden,
      default_index_used: record.default_index_used,
    })),
    validation_report_digest: input.validationReportDigest,
    simulation_report_digest: hexOrHash(input.simulation.simulation_digest),
    ipfs_cids: input.ipfsPins.map((pin) => ({
      cid: pin.cid,
      pin_target: pin.target,
    })),
    on_chain_tx_refs: [
      {
        chain_id: 31_337,
        tx_hash: hexToBytes32(input.event.txHash),
        block_number: input.event.blockNumber,
        event_name: "PDARegistered",
      },
    ],
  };
  assertCompleteInspection(inspection);
  return inspection;
}

export function assertCompleteInspection(inspection: PartnerReadableInspection): void {
  for (const field of PARTNER_INSPECTION_PRIMITIVE_FIELDS) {
    if (inspection[field] === undefined || inspection[field] === null) {
      throw new Error(`inspection missing primitive field ${field}`);
    }
  }
}

export function serializeInspection(inspection: PartnerReadableInspection): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of PARTNER_INSPECTION_PRIMITIVE_FIELDS) {
    out[field] = serializeValue(inspection[field]);
  }
  return out;
}

function schemaSummary(schema: unknown): string {
  const record = recordValue(schema);
  const fields = Array.isArray(record.fields) ? record.fields.length : 0;
  return `${String(fields)} schema fields`;
}

function oracleRefs(
  reveal: Record<string, unknown>,
  submitted: Record<string, unknown>,
): PartnerReadableInspection["oracle_refs"] {
  const signal = recordValue(reveal.k_of_n);
  const refs = Array.isArray(signal.oracle_refs) ? signal.oracle_refs : [];
  if (refs.length === 0) {
    return [
      {
        oracle_id: hashToBytes32("chain-native"),
        tier: trustTier(submitted.trust_tier),
        schema_ref: hashToBytes32("schema:default"),
      },
    ];
  }
  return refs.map((entry) => {
    const ref = recordValue(entry);
    return {
      oracle_id: hexOrHash(ref.oracle_id ?? ref.id ?? "oracle"),
      tier: trustTier(ref.tier),
      schema_ref: hexOrHash(ref.schema_ref ?? "schema:default"),
    };
  });
}

function recipientsSummary(value: unknown): PartnerReadableInspection["recipients_summary"] {
  if (!Array.isArray(value)) {
    return [{ role_tag: "RECIPIENT", delivery_mode: "PASSKEY_ACCOUNT", schema_selector: "$" }];
  }
  return value.map((entry) => {
    const recipient = recordValue(entry);
    return {
      role_tag: String(recipient.role_tag ?? "RECIPIENT"),
      delivery_mode: String(recipient.delivery_mode ?? "PASSKEY_ACCOUNT"),
      schema_selector: String(recipient.schema_selector ?? "$"),
    };
  });
}

function trustTier(value: unknown): "A" | "B" | "C" {
  return value === "B" || value === "C" ? value : "A";
}

function shredAuthority(value: unknown): PartnerReadableInspection["shred_authority"] {
  if (
    value === "Subject" ||
    value === "Joint" ||
    value === "Operator" ||
    value === "Timelock" ||
    value === "Disabled"
  ) {
    return value;
  }
  return "Subject";
}

function arrayStrings(value: unknown): readonly string[] {
  return Array.isArray(value) ? value.map((entry) => String(entry)) : [];
}

function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function toBigInt(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  return 0n;
}

function toNumber(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return 0;
}

function hexOrHash(value: unknown): Uint8Array {
  if (typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value)) return hexToBytes32(value);
  return hashToBytes32(value);
}

function serializeValue(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (value instanceof Map) {
    return Object.fromEntries([...value.entries()].map(([key, entry]) => [String(key), serializeValue(entry)]));
  }
  if (Array.isArray(value)) return value.map((entry) => serializeValue(entry));
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) out[key] = serializeValue(entry);
    return out;
  }
  return value;
}
