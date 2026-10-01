// PostgresIngestionRepository — the DB-backed `IngestionRepository` (T1.1).
//
// Replaces `InMemoryIngestionRepository` (see ./routes-create-mode-a.ts) with a
// real Postgres impl over the merged Wave-1 storage seam:
//
//   * `ingestions` (migration 0001) — the CANONICAL escrow row consumed by the
//     status route, the retention worker, and the reveal path. We project the
//     ingestion onto its real columns (vault_blob_ref, retention_expires_at,
//     commit_*, status, g3_choice, g4_phase, …).
//   * `idempotency_keys` (migration 0003) — the existing
//     (scope, idempotency_key, request_digest, response_body jsonb, …) table.
//     We reuse it under V3-ingestion-private scopes to persist the FULL
//     `IngestionRecord` envelope so the repository contract reconstructs the
//     EXACT record — including `idempotency_key` + `request_digest`, which the
//     `ingestions` table has no column for. Two scopes back the two readers:
//        - "v3:ingestion"            keyed by idempotency_key  → getByIdempotencyKey
//        - "v3:ingestion:by-hcommit" keyed by h_commit         → getByHCommit
//     Both rows carry the same `request_digest`, so the route's idempotency-
//     conflict check (existing.request_digest !== requestDigest) is preserved
//     byte-for-byte.
//
// Why an envelope instead of new columns: T1.1 owns only this impl file + its
// test; it does NOT own a migration. The `ingestions` schema (0001) carries no
// idempotency_key / request_digest column. The existing `idempotency_keys` table
// already has precisely the (scope, key, request_digest, jsonb body) shape
// needed, so the lossless envelope rides it under a private scope rather than
// perturbing the locked API table catalog (V3_API_TABLE_NAMES).
//
// The envelope is the AUTHORITATIVE round-trip: every `getBy*` read reconstructs
// the `IngestionRecord` from the jsonb body (lossless), not from the projected
// `ingestions` columns. The `ingestions` row exists so the rest of the runtime
// (status route, retention worker, reveal path) sees a real, query-shaped row.
//
// ── Interface shape (sync → async) ────────────────────────────────────────────
// The in-memory `IngestionRepository` interface is SYNCHRONOUS (an in-memory Map
// resolves synchronously). A Postgres repo cannot. This impl exposes the SAME
// method names with Promise-returning signatures (`AsyncIngestionRepository`).
// The default-swap in routes-create-mode-a.ts (await-ing these calls) is the
// Wave-5 composition wiring — NOT owned here. This file only builds the impl the
// composition root injects.
//
// ── GDPR / legal (internal legal-constraints rules) ─────────────────────────
//   * No PII at rest here. Stored: opaque digests/refs, the response envelope
//     (no plaintext payload — vault_ref is an opaque pointer), the
//     payload_classification CLASS label (not the payload), and retention
//     metadata. The plaintext payload is sealed into the vault by the VaultWriter
//     (T1.2) and never reaches this repository.
//   * `retention_expires_at` is persisted (PDA retention floor) so the retention
//     worker can enforce §195 BGB (obligation + 3y) crypto-shred timing.
//
// ── V3 isolation (SECURITY.md) ────────────────────────────────────
// No @cealis/shared, no V1 packages. The composition root injects the postgres-js
// `Sql` client (read from the V3-scoped env only — the sealed-share / issuer-salt
// / committee-key family is never read here). New DB (`cealis_v3_dev`), no FK
// across to V1.

import type { Sql } from "postgres";

import type { Hex32 } from "../h-commit/index.js";
import type {
  IngestionRecord,
  IngestionRepository,
} from "./routes-create-mode-a.js";

/** V3-private idempotency scope keyed by the partner Idempotency-Key header. */
export const INGESTION_IDEMPOTENCY_SCOPE = "v3:ingestion" as const;
/** V3-private idempotency scope keyed by h_commit (reverse-lookup envelope). */
export const INGESTION_BY_HCOMMIT_SCOPE = "v3:ingestion:by-hcommit" as const;

/**
 * Async variant of `IngestionRepository`. A Postgres-backed repo cannot satisfy
 * the synchronous in-memory contract, so every method returns a Promise. The
 * Wave-5 default-swap awaits these at the call sites in routes-create-mode-a.ts.
 * Method names are identical to `IngestionRepository`, so the swap is a pure
 * await-insertion, not a rename (enforced by `_AssertMethodParity` below).
 */
export interface AsyncIngestionRepository {
  getByIdempotencyKey(idempotencyKey: string): Promise<IngestionRecord | undefined>;
  getByHCommit(hCommit: Hex32): Promise<IngestionRecord | undefined>;
  save(record: IngestionRecord): Promise<void>;
}

export interface PostgresIngestionRepositoryOptions {
  /** postgres-js Sql client bound to the V3 DB (`cealis_v3_dev`). */
  readonly sql: Sql;
  /**
   * TTL (ms) for the idempotency envelope rows' `expires_at`. The canonical
   * `ingestions` row never expires (it is the durable escrow record); the
   * envelope tracks that durable record so a replayed Idempotency-Key keeps
   * returning the original commit for the life of the escrow. Default ~100y;
   * crypto-shred (not this TTL) enforces erasure. Override for tests.
   */
  readonly envelopeTtlMs?: number;
}

/** Row shape read back from `idempotency_keys` for an ingestion envelope. */
interface EnvelopeRow {
  readonly request_digest: string;
  readonly response_body: unknown;
}

/**
 * postgres-js may return a `jsonb` column as a parsed object OR a JSON string
 * depending on the column's CAST path (we INSERT via `${str}::jsonb`). Normalize
 * to the parsed object so the reconstructed record is identical to the in-memory
 * repository's.
 */
function parseEnvelope(value: unknown): IngestionRecord {
  if (typeof value === "string") {
    return JSON.parse(value) as IngestionRecord;
  }
  return value as IngestionRecord;
}

/**
 * The `ingestions` row needs two NOT NULL fields the typed `ModeAIngestionResponse`
 * does not declare (`schema_digest`, `payload_classification`) plus the optional
 * commit_block_hash / subject_commitment. The route DOES attach them to the
 * response object (its schema is `additionalProperties: true`), so we read them
 * off the response via this narrow accessor without an `as any`. Anything missing
 * is handled per-field in `projectRow` (defensible default or fail-loud).
 */
type ResponseRowFields = {
  readonly schema_digest?: string;
  readonly payload_classification?: Record<string, unknown>;
  readonly commit_block_hash?: string;
  readonly subject_commitment_v3?: string;
};

function rowFields(record: IngestionRecord): ResponseRowFields {
  return record.response as unknown as ResponseRowFields;
}

export class PostgresIngestionRepository implements AsyncIngestionRepository {
  private readonly sql: Sql;
  private readonly envelopeTtlMs: number;

  constructor(options: PostgresIngestionRepositoryOptions) {
    this.sql = options.sql;
    this.envelopeTtlMs = options.envelopeTtlMs ?? 100 * 365 * 24 * 60 * 60 * 1000;
  }

  async getByIdempotencyKey(idempotencyKey: string): Promise<IngestionRecord | undefined> {
    return this.readEnvelope(INGESTION_IDEMPOTENCY_SCOPE, idempotencyKey);
  }

  async getByHCommit(hCommit: Hex32): Promise<IngestionRecord | undefined> {
    return this.readEnvelope(INGESTION_BY_HCOMMIT_SCOPE, hCommit);
  }

  /**
   * Persist a committed ingestion. Writes — in ONE transaction — the canonical
   * `ingestions` row (consumed by the rest of the runtime) and the two
   * idempotency envelopes (by-key + by-h_commit) that back the repository
   * contract's lossless reconstruction.
   *
   * Idempotent: a re-save of the same (idempotency_key / h_commit) is a benign
   * no-op via `ON CONFLICT DO NOTHING` — a committed ingestion is immutable here.
   * The route's `getByIdempotencyKey` conflict check runs BEFORE save(), so by
   * the time save() runs the digest is known-consistent; ON CONFLICT guards only
   * the concurrent-replica race, never silently overwriting a committed row.
   */
  async save(record: IngestionRecord): Promise<void> {
    const r = record.response;
    const f = rowFields(record);

    if (typeof f.schema_digest !== "string") {
      // schema_digest is NOT NULL + CHECK regex on the ingestions row. The route
      // always attaches it to the response (additionalProperties: true). Fail
      // loud rather than write a bogus value — a producer bug, not a recoverable
      // runtime state (Rule 19: no fake-success).
      throw new Error(
        "PostgresIngestionRepository.save: response is missing schema_digest " +
          "required by the ingestions row",
      );
    }
    // Hoist the narrowed value to a local `string` — control-flow narrowing on a
    // property is invalidated across the function calls below, but the local is
    // stable for the INSERT interpolation.
    const schemaDigest: string = f.schema_digest;
    const subjectCommitment: string | null = f.subject_commitment_v3 ?? null;
    const commitBlockHash: string | null = f.commit_block_hash ?? null;
    const payloadClassificationJson = JSON.stringify(f.payload_classification ?? {});

    const envelopeJson = JSON.stringify(record);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.envelopeTtlMs);
    const requestDigest = record.request_digest;

    // One transaction: the canonical escrow row + both idempotency envelopes
    // commit atomically (or not at all). Each insert is `ON CONFLICT DO NOTHING`
    // — a re-save of an already-committed ingestion (idempotent retry /
    // concurrent replica) is a benign no-op, never a silent overwrite. Templates
    // are inlined in the callback (codebase idiom — see
    // postgres-reveal-repository.ts / postgres-vault-store.ts) rather than passed
    // to a helper, keeping the `TransactionSql` type on `tx`.
    await this.sql.begin(async (tx) => {
      // 1. Canonical escrow row.
      await tx`
        INSERT INTO ingestions (
          h_commit, authorization_id, pda_id, pda_version, partner_id,
          subject_commitment_v3, mode, g4_phase, g3_choice, schema_digest,
          payload_classification, vault_blob_ref, commit_block, commit_block_hash,
          commit_tx_hash, status, retention_expires_at
        ) VALUES (
          ${r.h_commit}, ${r.authorizationId}, ${r.pda_id}, ${r.pda_version},
          ${r.partner_id}, ${subjectCommitment}, ${"mode_a"},
          ${r.g4_phase ?? 2}, ${r.g3_choice ?? "dcipher"}, ${schemaDigest},
          ${payloadClassificationJson}::jsonb,
          ${r.vault_ref}, ${r.commit_block ?? null}, ${commitBlockHash},
          ${r.commit_tx_hash ?? null}, ${r.status},
          ${new Date(record.retention_status.retention_expires_at)}
        )
        ON CONFLICT (h_commit) DO NOTHING
      `;

      // 2. Idempotency envelope keyed by Idempotency-Key. response_status has no
      //    HTTP meaning for these private-scope envelopes (the route owns the
      //    201); store 201 as the truthful committed status so the NOT NULL
      //    column is satisfied without a sentinel.
      await tx`
        INSERT INTO idempotency_keys (
          scope, idempotency_key, request_digest, response_status, response_body,
          expires_at, created_at
        ) VALUES (
          ${INGESTION_IDEMPOTENCY_SCOPE}, ${record.idempotency_key}, ${requestDigest},
          ${201}, ${envelopeJson}::jsonb, ${expiresAt}, ${now}
        )
        ON CONFLICT (scope, idempotency_key) DO NOTHING
      `;

      // 3. Reverse-lookup envelope keyed by h_commit.
      await tx`
        INSERT INTO idempotency_keys (
          scope, idempotency_key, request_digest, response_status, response_body,
          expires_at, created_at
        ) VALUES (
          ${INGESTION_BY_HCOMMIT_SCOPE}, ${r.h_commit}, ${requestDigest},
          ${201}, ${envelopeJson}::jsonb, ${expiresAt}, ${now}
        )
        ON CONFLICT (scope, idempotency_key) DO NOTHING
      `;
    });
  }

  // ── private ────────────────────────────────────────────────────────────────

  private async readEnvelope(
    scope: string,
    key: string,
  ): Promise<IngestionRecord | undefined> {
    const rows = await this.sql<EnvelopeRow[]>`
      SELECT request_digest, response_body
      FROM idempotency_keys
      WHERE scope = ${scope} AND idempotency_key = ${key}
      LIMIT 1
    `;
    const row = rows[0];
    if (!row) return undefined;
    const record = parseEnvelope(row.response_body);
    // The persisted request_digest COLUMN is authoritative for the idempotency-
    // conflict check; re-attach it defensively (it equals the jsonb body's value,
    // written together in one tx).
    return { ...record, request_digest: row.request_digest as Hex32 };
  }
}

/**
 * Concrete async factory for the composition root. (A SYNCHRONOUS adapter to the
 * in-memory `IngestionRepository` shape is intentionally NOT provided: a Postgres
 * read is inherently async, so the runtime path must await. Wave-5 updates the
 * three call sites in routes-create-mode-a.ts to `await`.)
 */
export function createPostgresIngestionRepository(
  options: PostgresIngestionRepositoryOptions,
): PostgresIngestionRepository {
  return new PostgresIngestionRepository(options);
}

// Type-level guard: the async repo's method names are a superset of the sync
// `IngestionRepository` contract (same names, Promise-wrapped returns), so the
// Wave-5 swap is a pure await-insertion, not a rename.
type _AssertMethodParity = keyof IngestionRepository extends keyof AsyncIngestionRepository
  ? true
  : never;
const _methodParity: _AssertMethodParity = true;
void _methodParity;
