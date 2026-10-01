// PostgresRevealArtifactRepository — the DB-backed `RevealArtifactRepository`
// over the `reveals` table (migration 0002). Replaces
// `InMemoryRevealArtifactRepository` in the boot path (the in-memory class stays
// in ./persist.ts for unit tests).
//
// Table shape (`reveals`, PK `(authorization_id, recipient_ref)`):
//   - one STATUS-HEADER row per authorization, under the sentinel recipient_ref
//     `__status__`, carrying the manifest (`manifest` jsonb) + the
//     authorization-level status record (`bundle` jsonb: status, g4_phase,
//     challenge_window_expired_at, refusal). It bears NO artifact bundle.
//   - one BUNDLE row per real recipient_ref, carrying the assembled
//     `RevealArtifactBundle` (`bundle` jsonb) + its digest + storage ref.
//
// `getStatus` reconstructs `RevealStatusRecord.artifact_bundles` by reading every
// bundle row for the authorization — so the per-recipient bundle descriptors are
// derived from the source-of-truth rows, never a denormalized copy that can drift.
//
// Lifecycle parity with the in-memory impl (./persist.ts):
//   upsertStatus → write/merge the status-header row.
//   putManifest  → write the manifest into the status-header row (create it if the
//                  combiner called putManifest before upsertStatus — defensive).
//   putBundle    → write the recipient bundle row AND flip the status-header to
//                  `finalized`, preserving g4_phase + challenge_window from either
//                  the bundle or the existing header (mirrors InMemory.putBundle).
//
// GDPR (internal legal-constraints rules): the `reveals` table holds reveal
// DELIVERY artifacts (post-authorization, recipient-filtered plaintext). It is NOT
// the issuer plaintext-PII store (deleted after KYC) nor the vault. Retention is
// the orchestrator-delivery-log floor (3y §195 BGB); no append-only trigger here —
// that invariant lives on `vault_audit_log`.
//
// V3 isolation (SECURITY.md): caller-injected `Sql`; no @cealis/shared,
// no V1 packages, no V1 env vars. Raw postgres-js tagged templates (the codebase
// store idiom: see auth/postgres-*-store.ts, vault/backends/postgres-vault-store.ts).

import type { Sql } from "postgres";
import type { CombinerManifest } from "../types/combiner-manifest.js";
import type { Hex32, RevealArtifactBundle } from "../types/reveal-artifact-bundle.js";
import type {
  PersistedBundleRecord,
  RevealArtifactRepository,
  RevealDeliveryStatus,
  RevealStatusRecord,
} from "./persist.js";

/**
 * Sentinel `recipient_ref` for the authorization-level status-header row. A real
 * recipient_ref is a recipient identifier; this sentinel is reserved and can never
 * collide with one (real recipient refs do not contain the double-underscore guard
 * token). The header row holds manifest + status, never an artifact bundle.
 */
export const STATUS_HEADER_RECIPIENT_REF = "__status__" as const;

export interface PostgresRevealArtifactRepositoryOptions {
  /** postgres-js Sql client bound to the V3 DB (`cealis_v3_dev`). */
  readonly sql: Sql;
}

/** Shape of the authorization-level status payload persisted in the header row's
 *  `bundle` jsonb column (the artifact_bundles array is NOT stored here — it is
 *  reconstructed from the per-recipient rows on read). */
interface StatusHeaderPayload {
  readonly status: RevealDeliveryStatus;
  readonly g4_phase: 1 | 2;
  readonly challenge_window_expired_at?: string;
  readonly refusal?: Record<string, unknown>;
}

interface HeaderRow {
  readonly h_commit: string;
  readonly status: string;
  readonly g4_phase: number;
  readonly challenge_window_expired_at: Date | null;
  readonly manifest: unknown;
  readonly bundle: unknown;
}

interface BundleRow {
  readonly recipient_ref: string;
  readonly h_commit: string;
  readonly bundle_digest: string | null;
  readonly bundle_storage_ref: string | null;
  readonly status: string;
  readonly finalized_at: Date | null;
  readonly bundle: unknown;
}

/** postgres-js may return a jsonb column as a parsed object OR a JSON string
 *  (depends on the column's CAST path; we INSERT via `${str}::jsonb`). Normalize
 *  to the parsed value so callers see the same object shape they wrote. */
function parseJson<T>(value: unknown): T | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") return JSON.parse(value) as T;
  return value as T;
}

export class PostgresRevealArtifactRepository implements RevealArtifactRepository {
  private readonly sql: Sql;

  constructor(options: PostgresRevealArtifactRepositoryOptions) {
    this.sql = options.sql;
  }

  async upsertStatus(status: RevealStatusRecord): Promise<void> {
    const payload: StatusHeaderPayload = {
      status: status.status,
      g4_phase: status.g4_phase,
      ...(status.challenge_window_expired_at === undefined
        ? {}
        : { challenge_window_expired_at: status.challenge_window_expired_at }),
      ...(status.refusal === undefined ? {} : { refusal: status.refusal }),
    };
    await this.writeHeaderStatus(status.authorizationId, status.h_commit, payload);
  }

  async getStatus(authorizationId: Hex32): Promise<RevealStatusRecord | undefined> {
    const rows = await this.sql<HeaderRow[]>`
      SELECT h_commit, status, g4_phase, challenge_window_expired_at, manifest, bundle
      FROM reveals
      WHERE authorization_id = ${authorizationId} AND recipient_ref = ${STATUS_HEADER_RECIPIENT_REF}
    `;
    const header = rows[0];
    if (!header) return undefined;

    const payload = parseJson<StatusHeaderPayload>(header.bundle);
    const artifactBundles = await this.readBundleDescriptors(authorizationId);

    return {
      authorizationId,
      h_commit: header.h_commit as Hex32,
      status: header.status as RevealDeliveryStatus,
      g4_phase: (payload?.g4_phase ?? header.g4_phase) as 1 | 2,
      ...(this.resolveChallengeWindow(payload, header) === undefined
        ? {}
        : { challenge_window_expired_at: this.resolveChallengeWindow(payload, header)! }),
      ...(payload?.refusal === undefined ? {} : { refusal: payload.refusal }),
      ...(artifactBundles.length === 0 ? {} : { artifact_bundles: artifactBundles }),
    };
  }

  async putManifest(authorizationId: Hex32, manifest: CombinerManifest): Promise<void> {
    const manifestJson = JSON.stringify(manifest);
    // The status-header row may not exist yet if putManifest lands before
    // upsertStatus (defensive — the combiner always calls upsertStatus first, but
    // the contract does not mandate ordering). Create a minimal header carrying
    // the manifest; status defaults to "authorized", g4_phase from the manifest.
    const updated = await this.sql<{ recipient_ref: string }[]>`
      UPDATE reveals
        SET manifest = ${manifestJson}::jsonb, updated_at = now()
      WHERE authorization_id = ${authorizationId} AND recipient_ref = ${STATUS_HEADER_RECIPIENT_REF}
      RETURNING recipient_ref
    `;
    if (updated.length > 0) return;

    await this.sql`
      INSERT INTO reveals (
        authorization_id, h_commit, recipient_ref, status, g4_phase, manifest, created_at, updated_at
      ) VALUES (
        ${authorizationId}, ${manifest.h_commit}, ${STATUS_HEADER_RECIPIENT_REF},
        ${"authorized"}, ${manifest.g4_phase}, ${manifestJson}::jsonb, now(), now()
      )
      ON CONFLICT (authorization_id, recipient_ref) DO UPDATE
        SET manifest = EXCLUDED.manifest, updated_at = now()
    `;
  }

  async getManifest(authorizationId: Hex32): Promise<CombinerManifest | undefined> {
    const rows = await this.sql<{ manifest: unknown }[]>`
      SELECT manifest FROM reveals
      WHERE authorization_id = ${authorizationId} AND recipient_ref = ${STATUS_HEADER_RECIPIENT_REF}
    `;
    return parseJson<CombinerManifest>(rows[0]?.manifest);
  }

  async putBundle(record: PersistedBundleRecord): Promise<void> {
    if (record.recipient_ref === STATUS_HEADER_RECIPIENT_REF) {
      throw new Error(
        `PostgresRevealArtifactRepository: recipient_ref "${STATUS_HEADER_RECIPIENT_REF}" is reserved for the status header`,
      );
    }
    const bundleJson = JSON.stringify(record.bundle);

    // Persist the per-recipient bundle row + flip the status header to
    // "finalized" atomically (mirrors InMemoryRevealArtifactRepository.putBundle:
    // writing a bundle implies the authorization reached the finalized state).
    await this.sql.begin(async (tx) => {
      await tx`
        INSERT INTO reveals (
          authorization_id, h_commit, recipient_ref, bundle_digest, bundle_storage_ref,
          status, g4_phase, bundle, finalized_at, created_at, updated_at
        ) VALUES (
          ${record.authorizationId}, ${record.h_commit}, ${record.recipient_ref},
          ${record.bundle_digest}, ${record.bundle_storage_ref}, ${record.status},
          ${record.bundle.sigma_block.sigma_g4.phase ?? 2}, ${bundleJson}::jsonb,
          ${record.finalized_at === undefined ? null : new Date(record.finalized_at)},
          now(), now()
        )
        ON CONFLICT (authorization_id, recipient_ref) DO UPDATE
          SET bundle_digest = EXCLUDED.bundle_digest,
              bundle_storage_ref = EXCLUDED.bundle_storage_ref,
              status = EXCLUDED.status,
              g4_phase = EXCLUDED.g4_phase,
              bundle = EXCLUDED.bundle,
              finalized_at = EXCLUDED.finalized_at,
              updated_at = now()
      `;

      // Read the current header (if any) inside the tx to preserve its
      // g4_phase + challenge_window fallbacks, exactly like the in-memory merge.
      const headerRows = await tx<HeaderRow[]>`
        SELECT h_commit, status, g4_phase, challenge_window_expired_at, manifest, bundle
        FROM reveals
        WHERE authorization_id = ${record.authorizationId} AND recipient_ref = ${STATUS_HEADER_RECIPIENT_REF}
      `;
      const currentPayload = parseJson<StatusHeaderPayload>(headerRows[0]?.bundle);
      const headerRow = headerRows[0];

      const g4Phase = (record.bundle.sigma_block.sigma_g4.phase ??
        currentPayload?.g4_phase ??
        headerRow?.g4_phase ??
        2) as 1 | 2;
      const challengeWindow =
        this.resolveChallengeWindow(currentPayload, headerRow) ??
        record.bundle.authorization.challenge_window_expired_at;

      const payload: StatusHeaderPayload = {
        status: "finalized",
        g4_phase: g4Phase,
        ...(challengeWindow === undefined ? {} : { challenge_window_expired_at: challengeWindow }),
        ...(currentPayload?.refusal === undefined ? {} : { refusal: currentPayload.refusal }),
      };
      await this.writeHeaderStatusTx(tx, record.authorizationId, record.h_commit, payload);
    });
  }

  async getBundle(
    authorizationId: Hex32,
    recipientRef: string,
  ): Promise<PersistedBundleRecord | undefined> {
    if (recipientRef === STATUS_HEADER_RECIPIENT_REF) return undefined;
    const rows = await this.sql<BundleRow[]>`
      SELECT recipient_ref, h_commit, bundle_digest, bundle_storage_ref, status, finalized_at, bundle
      FROM reveals
      WHERE authorization_id = ${authorizationId} AND recipient_ref = ${recipientRef}
    `;
    const row = rows[0];
    if (!row) return undefined;
    return this.rowToBundleRecord(authorizationId, row);
  }

  async listBundles(authorizationId: Hex32): Promise<readonly PersistedBundleRecord[]> {
    const rows = await this.sql<BundleRow[]>`
      SELECT recipient_ref, h_commit, bundle_digest, bundle_storage_ref, status, finalized_at, bundle
      FROM reveals
      WHERE authorization_id = ${authorizationId} AND recipient_ref <> ${STATUS_HEADER_RECIPIENT_REF}
      ORDER BY created_at ASC, recipient_ref ASC
    `;
    return rows.map((row) => this.rowToBundleRecord(authorizationId, row));
  }

  // --- internals -----------------------------------------------------------

  /** Reconstruct the per-recipient bundle descriptors for `getStatus`. */
  private async readBundleDescriptors(
    authorizationId: Hex32,
  ): Promise<NonNullable<RevealStatusRecord["artifact_bundles"]>> {
    const rows = await this.sql<
      {
        recipient_ref: string;
        bundle_digest: string | null;
        bundle_storage_ref: string | null;
        status: string;
      }[]
    >`
      SELECT recipient_ref, bundle_digest, bundle_storage_ref, status
      FROM reveals
      WHERE authorization_id = ${authorizationId} AND recipient_ref <> ${STATUS_HEADER_RECIPIENT_REF}
      ORDER BY created_at ASC, recipient_ref ASC
    `;
    return rows.map((row) => ({
      recipient_ref: row.recipient_ref,
      bundle_digest: (row.bundle_digest ?? "0x") as Hex32,
      bundle_storage_ref: row.bundle_storage_ref ?? "",
      status: row.status as RevealDeliveryStatus,
    }));
  }

  private rowToBundleRecord(authorizationId: Hex32, row: BundleRow): PersistedBundleRecord {
    const bundle = parseJson<RevealArtifactBundle>(row.bundle);
    if (bundle === undefined) {
      throw new Error(
        `PostgresRevealArtifactRepository: reveals row ${authorizationId}/${row.recipient_ref} has no bundle payload`,
      );
    }
    return {
      authorizationId,
      h_commit: row.h_commit as Hex32,
      recipient_ref: row.recipient_ref,
      bundle_digest: (row.bundle_digest ?? "0x") as Hex32,
      bundle_storage_ref: row.bundle_storage_ref ?? "",
      status: row.status as RevealDeliveryStatus,
      ...(row.finalized_at === null
        ? {}
        : { finalized_at: row.finalized_at.toISOString() }),
      bundle,
    };
  }

  private resolveChallengeWindow(
    payload: StatusHeaderPayload | undefined,
    header: HeaderRow | undefined,
  ): string | undefined {
    if (payload?.challenge_window_expired_at !== undefined) {
      return payload.challenge_window_expired_at;
    }
    if (header?.challenge_window_expired_at) {
      return header.challenge_window_expired_at.toISOString();
    }
    return undefined;
  }

  private async writeHeaderStatus(
    authorizationId: Hex32,
    hCommit: Hex32,
    payload: StatusHeaderPayload,
  ): Promise<void> {
    await this.writeHeaderStatusTx(this.sql, authorizationId, hCommit, payload);
  }

  /** Upsert the status-header row, preserving any manifest already written. The
   *  status fields live in the `bundle` jsonb (status payload); the dedicated
   *  `status`/`g4_phase`/`challenge_window_expired_at` columns are kept in sync so
   *  SQL-level filtering (e.g. the reveals_status_idx) still works. */
  private async writeHeaderStatusTx(
    sql: Sql,
    authorizationId: Hex32,
    hCommit: Hex32,
    payload: StatusHeaderPayload,
  ): Promise<void> {
    const payloadJson = JSON.stringify(payload);
    const challengeWindow =
      payload.challenge_window_expired_at === undefined
        ? null
        : new Date(payload.challenge_window_expired_at);
    await sql`
      INSERT INTO reveals (
        authorization_id, h_commit, recipient_ref, status, g4_phase,
        challenge_window_expired_at, bundle, created_at, updated_at
      ) VALUES (
        ${authorizationId}, ${hCommit}, ${STATUS_HEADER_RECIPIENT_REF},
        ${payload.status}, ${payload.g4_phase}, ${challengeWindow},
        ${payloadJson}::jsonb, now(), now()
      )
      ON CONFLICT (authorization_id, recipient_ref) DO UPDATE
        SET h_commit = EXCLUDED.h_commit,
            status = EXCLUDED.status,
            g4_phase = EXCLUDED.g4_phase,
            challenge_window_expired_at = EXCLUDED.challenge_window_expired_at,
            bundle = EXCLUDED.bundle,
            updated_at = now()
    `;
  }
}
