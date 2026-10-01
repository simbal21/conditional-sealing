// Postgres-backed WRAPPED share-stanza store + loader (F-WRAP-1 persistence seam).
//
// Extracted from the composition root so the same real DB code backs both the
// boot wiring and the real-stack E2E. INSERT writes ONLY wrapped per-gate stanzas
// (the §6.2 hybrid-wrap payload) + public routing/digest metadata to
// `dek_share_records`; the loader reads ONE gate's wrapped stanza at reveal. No
// raw share, no DEK, no plaintext ever passes through here.
//
// V3 isolation: V3 DB namespace only; no @cealis/shared, no V1 env vars.

import type { Sql } from "postgres";

import type { Hex32 } from "../h-commit/index.js";
import type { ShareRecordStore } from "../ingest/vault-writer-impl.js";
import type { WrappedShareRecord } from "../ingest/wrap-shares.js";
import type { GateWrappedStanza } from "../combiner-orchestrator/gate-unwrap.js";
import type { WrappedStanzaLoader } from "./local-gate-keys.js";

/**
 * DB-backed ShareRecordStore — INSERT the WRAPPED per-gate stanzas into
 * `dek_share_records` (migration 0006). Each row carries the §6.2 wrapped payload
 * (decryptable only by its gate's private key) + the routing/public-digest
 * metadata. NEVER a raw share. Idempotent on the composite PK so a retried ingest
 * is a benign no-op.
 */
export class PostgresWrappedShareStore implements ShareRecordStore {
  constructor(private readonly sql: Sql) {}

  async persist(input: {
    readonly h_commit: Hex32;
    readonly records: readonly WrappedShareRecord[];
  }): Promise<void> {
    await this.sql.begin(async (tx) => {
      for (const r of input.records) {
        await tx`
          INSERT INTO dek_share_records (
            h_commit, stanza_index, gate_kind, conditional_recipient_index,
            role, domain, logical_index, x, binding_tag, wrapped_payload,
            plugin_version_digest, commit_context_digest_n, commit_context_digest_0
          )
          VALUES (
            ${input.h_commit}, ${r.stanza_index}, ${r.gate_kind}, ${r.conditional_recipient_index},
            ${r.share_role}, ${r.share_domain}, ${r.logical_index}, ${r.x}, ${r.binding_tag},
            ${Buffer.from(r.wrapped_payload)},
            ${Buffer.from(r.plugin_version_digest)}, ${Buffer.from(r.commit_context_digest_N)},
            ${Buffer.from(r.commit_context_digest_0)}
          )
          ON CONFLICT (h_commit, stanza_index) DO NOTHING
        `;
      }
    });
  }
}

/**
 * DB-backed wrapped-stanza loader — read ONE gate's wrapped stanza routing record
 * from `dek_share_records` at reveal. Used by the gate-unwrap source so a gate can
 * decode + unwrap its own stanza. Returns no DEK, no plaintext — only the gate's
 * own wrapped payload (opaque without that gate's private key).
 */
export function makeWrappedStanzaLoader(sql: Sql): WrappedStanzaLoader {
  return async (input): Promise<GateWrappedStanza> => {
    const rows = await sql<
      {
        stanza_index: number;
        binding_tag: string;
        domain: number;
        role: number;
        logical_index: number;
        x: number;
        wrapped_payload: Buffer;
        plugin_version_digest: Buffer;
        commit_context_digest_n: Buffer;
        commit_context_digest_0: Buffer;
      }[]
    >`
      SELECT stanza_index, binding_tag, domain, role, logical_index, x, wrapped_payload,
             plugin_version_digest, commit_context_digest_n, commit_context_digest_0
      FROM dek_share_records
      WHERE h_commit = ${input.hCommit}
        AND gate_kind = ${input.gateKind}
        AND conditional_recipient_index = ${input.conditionalRecipientIndex}
      LIMIT 1
    `;
    const row = rows[0];
    if (row === undefined) {
      throw new Error(
        `no wrapped stanza in dek_share_records for h_commit=${input.hCommit} ` +
          `gate=${input.gateKind} cr=${input.conditionalRecipientIndex}`,
      );
    }
    return {
      stanza_index: row.stanza_index,
      binding_tag: row.binding_tag as Hex32,
      share_domain: row.domain,
      share_role: row.role,
      logical_index: row.logical_index,
      x: row.x,
      wrapped_payload: new Uint8Array(row.wrapped_payload),
      plugin_version_digest: new Uint8Array(row.plugin_version_digest),
      commit_context_digest_N: new Uint8Array(row.commit_context_digest_n),
      commit_context_digest_0: new Uint8Array(row.commit_context_digest_0),
    };
  };
}
