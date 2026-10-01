import type { AuditTrailRecord } from "../types/audit-trail.js";
import { findPiiMatch } from "../types/audit-trail.js";
import { bytesToHex, hashToBytes32 } from "./pda-root.js";

export interface AuditTrailInput {
  readonly submitted: Record<string, unknown>;
  readonly validationDigest: Uint8Array;
  readonly validationPass: boolean;
  readonly stagePasses: readonly [boolean, boolean, boolean, boolean, boolean];
  readonly failureCount: number;
  readonly simulationDigest: string;
  readonly pdaRoot: Uint8Array;
  readonly ipfsCids: readonly string[];
  readonly txRefs: AuditTrailRecord["on_chain_tx_refs"];
  readonly recordedAtUnixSeconds?: bigint;
}

export function recordAuditTrail(input: AuditTrailInput): AuditTrailRecord {
  const record: AuditTrailRecord = {
    input_form_digest: hashToBytes32(input.submitted),
    translated_pda_json_digest: hashToBytes32({ pda: input.submitted, normalized: true }),
    template_ids: [hashToBytes32(input.submitted.template_id ?? "template:none")],
    validation_result_set: {
      digest: input.validationDigest,
      pass: input.validationPass,
      stage1_pass: input.stagePasses[0],
      stage2_pass: input.stagePasses[1],
      stage3_pass: input.stagePasses[2],
      stage4_pass: input.stagePasses[3],
      stage5_pass: input.stagePasses[4],
      failure_count: input.failureCount,
    },
    simulation_result_digest: hashToBytes32(input.simulationDigest),
    human_reviewer_identity_digest: hashToBytes32("cealis-internal-reviewer"),
    emitted_pda_root: input.pdaRoot,
    ipfs_cids: input.ipfsCids,
    on_chain_tx_refs: input.txRefs,
    recorded_at_unix_seconds: input.recordedAtUnixSeconds ?? 0n,
  };
  assertAuditTrailClean(record);
  return record;
}

export function assertAuditTrailClean(record: AuditTrailRecord): void {
  const serialized = JSON.stringify(record, (_key, value: unknown) => {
    if (typeof value === "bigint") return value.toString();
    if (value instanceof Uint8Array) return bytesToHex(value);
    return value;
  });
  const match = findPiiMatch(serialized);
  if (match !== null) {
    throw new Error(`audit trail contains excluded marker ${match}`);
  }
}
