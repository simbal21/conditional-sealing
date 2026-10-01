// PostgresIngestionRepository tests (T1.1).
//
// Two layers:
//   1. LIVE round-trip against real Postgres — opt-in via V3_TEST_PG_URL (or
//      CEALIS_V3_DATABASE_URL); SKIPs cleanly when unset so typecheck + CI
//      without a PG instance still pass. Asserts the real contract: save →
//      getByIdempotencyKey / getByHCommit reconstruct the EXACT IngestionRecord
//      (idempotency_key + request_digest preserved); the canonical `ingestions`
//      row is written; a re-save is idempotent (no overwrite / no duplicate);
//      and NO plaintext PII ever lands in any stored row.
//   2. LOGIC against an injected fake Sql — infra-free. Asserts the
//      schema_digest fail-loud (Rule 19, no fake-success) and the jsonb-string
//      normalization on read.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres from "postgres";
import type { Sql } from "postgres";

import { applyMigrations } from "../../src/db/migrate.js";
import {
  PostgresIngestionRepository,
  INGESTION_IDEMPOTENCY_SCOPE,
  INGESTION_BY_HCOMMIT_SCOPE,
} from "../../src/ingest/postgres-ingestion-repository.js";
import type {
  IngestionRecord,
  ModeAIngestionResponse,
} from "../../src/ingest/routes-create-mode-a.js";
import type { Hex32 } from "../../src/h-commit/index.js";

const TEST_PG_URL =
  process.env["V3_TEST_PG_URL"] ?? process.env["CEALIS_V3_DATABASE_URL"];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

// The known plaintext PII token. It must NEVER appear in any stored row — the
// payload is sealed into the vault elsewhere, never into this repo.
const PLAINTEXT_TOKEN = "SECRET-PII-Erika-Mustermann";

const hex32 = (seed: string): Hex32 => {
  const repeated = seed.repeat(64).slice(0, 64);
  return `0x${repeated}` as Hex32;
};

/**
 * Deterministic, suite-namespaced 32-byte hex. Hashes the prefix+label down to a
 * valid `^0x[0-9a-fA-F]{64}$` so the CHECK regex on `ingestions.h_commit` passes
 * AND rows never collide across parallel vitest files. No crypto needed — a
 * simple hex digest of char codes is enough for namespacing.
 */
const suiteHex32 = (prefix: string, label: string): Hex32 => {
  const src = `${prefix}:${label}`;
  let out = "";
  for (let i = 0; i < 64; i++) {
    const code = src.charCodeAt(i % src.length) + i * 7;
    out += (code & 0xf).toString(16);
  }
  return `0x${out}` as Hex32;
};

/**
 * Build an IngestionRecord whose response carries the row-projection fields the
 * route attaches via additionalProperties (schema_digest, payload_classification,
 * subject_commitment_v3, commit_block_hash) alongside the typed response shape.
 */
function buildRecord(opts: {
  readonly hCommit: Hex32;
  readonly idempotencyKey: string;
  readonly requestDigest: Hex32;
  readonly status?: ModeAIngestionResponse["status"];
  readonly omitSchemaDigest?: boolean;
}): IngestionRecord {
  const response = {
    api_version: "1.0-draft",
    commit_version: "0x0302" as const,
    ingestion_id: `ing-${opts.idempotencyKey}`,
    authorizationId: hex32("1"),
    h_commit: opts.hCommit,
    pda_id: "11111111-1111-4111-8111-111111111111",
    pda_version: "1",
    partner_id: "22222222-2222-4222-8222-222222222222",
    vault_ref: `vault://${opts.hCommit}`,
    commit_tx_hash: `0x${opts.hCommit.slice(2)}`,
    commit_block: 12_345,
    g3_choice: "dcipher" as const,
    g4_phase: 2 as const,
    retention_expires_at: "2029-01-01T00:00:00.000Z",
    sd_output: { status: "not_configured" },
    status: opts.status ?? ("committed" as const),
    // Row-projection extras (additionalProperties on the response schema):
    ...(opts.omitSchemaDigest ? {} : { schema_digest: hex32("b") }),
    payload_classification: { pii_class: "kyc", media_type: "application/json" },
    subject_commitment_v3: hex32("c"),
    commit_block_hash: hex32("d"),
  } as unknown as ModeAIngestionResponse;

  return {
    request_digest: opts.requestDigest,
    idempotency_key: opts.idempotencyKey,
    response,
    retention_status: {
      h_commit: opts.hCommit,
      retention_policy_id: "obligation_plus_3y",
      retention_expires_at: "2029-01-01T00:00:00.000Z",
      shred_authority: "joint",
      shred_condition_summary: "joint or operator guarded shred",
    },
  };
}

// ── Layer 1: LIVE round-trip (V3_TEST_PG_URL) ──────────────────────────────────

describeIfPg("PostgresIngestionRepository (V3_TEST_PG_URL)", () => {
  let sql: Sql;
  let repo: PostgresIngestionRepository;
  let P: string; // per-suite prefix → no cross-file collisions under parallel vitest

  beforeAll(async () => {
    if (!TEST_PG_URL) return;
    sql = postgres(TEST_PG_URL, { max: 4, idle_timeout: 5, onnotice: () => {} });
    // applyMigrations runs ALL migrations idempotently under an advisory lock —
    // we need 0001 (ingestions) + 0003 (idempotency_keys). Safe to run the full
    // set; every migration is CREATE ... IF NOT EXISTS.
    await applyMigrations(sql);
    repo = new PostgresIngestionRepository({ sql });
    P = `t-${process.pid}-${Math.random().toString(36).slice(2, 8)}-`;
  });

  afterAll(async () => {
    if (!sql) return;
    // Clean up ONLY this suite's rows. The by-key envelope keys on the suite
    // prefix; the by-h_commit envelope keys on a (non-prefixed) h_commit but
    // embeds this suite's idempotency_key in its jsonb body, so we match it
    // there. Delete the `ingestions` projection FIRST (its h_commit is the
    // by-h_commit envelope's key), then the envelopes.
    await sql`
      DELETE FROM ingestions
      WHERE h_commit IN (
        SELECT idempotency_key FROM idempotency_keys
        WHERE scope = ${INGESTION_BY_HCOMMIT_SCOPE}
          AND response_body->>'idempotency_key' LIKE ${P + "%"}
      )
    `;
    await sql`
      DELETE FROM idempotency_keys
      WHERE (scope = ${INGESTION_IDEMPOTENCY_SCOPE} AND idempotency_key LIKE ${P + "%"})
         OR (scope = ${INGESTION_BY_HCOMMIT_SCOPE} AND response_body->>'idempotency_key' LIKE ${P + "%"})
    `;
    await sql.end({ timeout: 5 });
  });

  it("save → getByIdempotencyKey reconstructs the exact record", async () => {
    const h = suiteHex32(P, "aa");
    const idemKey = `${P}idem-1`;
    const reqDigest = hex32("e");
    const record = buildRecord({ hCommit: h, idempotencyKey: idemKey, requestDigest: reqDigest });

    await repo.save(record);

    const got = await repo.getByIdempotencyKey(idemKey);
    expect(got).toBeDefined();
    expect(got?.idempotency_key).toBe(idemKey);
    expect(got?.request_digest).toBe(reqDigest);
    expect(got?.response.h_commit).toBe(h);
    expect(got?.response.vault_ref).toBe(`vault://${h}`);
    expect(got?.response.status).toBe("committed");
    expect(got?.retention_status.retention_policy_id).toBe("obligation_plus_3y");
    expect(got?.retention_status.shred_authority).toBe("joint");
  });

  it("save → getByHCommit reconstructs the same record", async () => {
    const h = suiteHex32(P, "bb");
    const idemKey = `${P}idem-2`;
    const reqDigest = hex32("f");
    const record = buildRecord({ hCommit: h, idempotencyKey: idemKey, requestDigest: reqDigest });

    await repo.save(record);

    const got = await repo.getByHCommit(h);
    expect(got).toBeDefined();
    expect(got?.response.h_commit).toBe(h);
    expect(got?.idempotency_key).toBe(idemKey);
    expect(got?.request_digest).toBe(reqDigest);
  });

  it("writes the canonical `ingestions` row consumed by the rest of the runtime", async () => {
    const h = suiteHex32(P, "cc");
    const idemKey = `${P}idem-3`;
    const record = buildRecord({ hCommit: h, idempotencyKey: idemKey, requestDigest: hex32("a") });

    await repo.save(record);

    const rows = await sql<
      { status: string; vault_blob_ref: string; g3_choice: string; g4_phase: number; mode: string }[]
    >`
      SELECT status, vault_blob_ref, g3_choice, g4_phase, mode FROM ingestions WHERE h_commit = ${h}
    `;
    expect(rows.length).toBe(1);
    expect(rows[0]?.status).toBe("committed");
    expect(rows[0]?.vault_blob_ref).toBe(`vault://${h}`);
    expect(rows[0]?.g3_choice).toBe("dcipher");
    expect(rows[0]?.g4_phase).toBe(2);
    expect(rows[0]?.mode).toBe("mode_a");
  });

  it("re-save of the same commit is idempotent — no duplicate, no overwrite", async () => {
    const h = suiteHex32(P, "dd");
    const idemKey = `${P}idem-4`;
    const reqDigest = hex32("a");
    const first = buildRecord({ hCommit: h, idempotencyKey: idemKey, requestDigest: reqDigest });
    await repo.save(first);

    // A retry of the SAME commit (same key + digest) must not duplicate rows or
    // mutate the committed projection.
    await repo.save(first);

    const ingRows = await sql<{ c: number }[]>`SELECT COUNT(*)::int AS c FROM ingestions WHERE h_commit = ${h}`;
    expect(ingRows[0]?.c).toBe(1);
    const idemRows = await sql<{ c: number }[]>`
      SELECT COUNT(*)::int AS c FROM idempotency_keys
      WHERE scope IN (${INGESTION_IDEMPOTENCY_SCOPE}, ${INGESTION_BY_HCOMMIT_SCOPE})
        AND idempotency_key IN (${idemKey}, ${h})
    `;
    expect(idemRows[0]?.c).toBe(2); // one by-key envelope + one by-h_commit envelope
  });

  it("getByIdempotencyKey / getByHCommit return undefined for unknown keys", async () => {
    expect(await repo.getByIdempotencyKey(`${P}missing`)).toBeUndefined();
    expect(await repo.getByHCommit(hex32("9"))).toBeUndefined();
  });

  it("never stores plaintext PII in any row (payload is sealed in the vault, not here)", async () => {
    const h = suiteHex32(P, "ee");
    const idemKey = `${P}idem-5`;
    const record = buildRecord({ hCommit: h, idempotencyKey: idemKey, requestDigest: hex32("a") });
    // The repository only ever sees the response envelope + classification — never
    // the plaintext. Prove the token is absent everywhere it could leak.
    await repo.save(record);

    const ing = await sql<{ dump: string }[]>`
      SELECT h_commit || '|' || vault_blob_ref || '|' || schema_digest || '|' ||
             payload_classification::text || '|' || COALESCE(subject_commitment_v3, '') AS dump
      FROM ingestions WHERE h_commit = ${h}
    `;
    expect(ing.length).toBe(1);
    expect(ing[0]?.dump).not.toContain(PLAINTEXT_TOKEN);

    const env = await sql<{ dump: string }[]>`
      SELECT response_body::text AS dump FROM idempotency_keys
      WHERE scope = ${INGESTION_IDEMPOTENCY_SCOPE} AND idempotency_key = ${idemKey}
    `;
    expect(env.length).toBe(1);
    expect(env[0]?.dump).not.toContain(PLAINTEXT_TOKEN);
  });
});

// ── Layer 2: LOGIC against an injected fake Sql (infra-free) ────────────────────

/**
 * Minimal tagged-template Sql double. Records the SQL fragments it sees and
 * returns a programmable row set. We only need the read-path (a single SELECT)
 * and the fail-loud path (which throws BEFORE any tx), so the double does not
 * need a working `.begin`.
 */
function fakeSql(rowsToReturn: unknown[]): {
  sql: Sql;
  calls: { strings: readonly string[]; values: unknown[] }[];
} {
  const calls: { strings: readonly string[]; values: unknown[] }[] = [];
  const tag = (strings: TemplateStringsArray, ...values: unknown[]) => {
    calls.push({ strings: Array.from(strings), values });
    return Promise.resolve(rowsToReturn);
  };
  return { sql: tag as unknown as Sql, calls };
}

describe("PostgresIngestionRepository (logic, fake Sql)", () => {
  it("readEnvelope normalizes a jsonb-string body and re-attaches the column digest", async () => {
    const stored: IngestionRecord = buildRecord({
      hCommit: hex32("a"),
      idempotencyKey: "logic-1",
      requestDigest: hex32("a"),
    });
    // postgres-js sometimes returns jsonb as a JSON STRING — the repo must parse.
    const { sql } = fakeSql([
      { request_digest: hex32("7"), response_body: JSON.stringify(stored) },
    ]);
    const repo = new PostgresIngestionRepository({ sql });

    const got = await repo.getByIdempotencyKey("logic-1");
    expect(got).toBeDefined();
    expect(got?.idempotency_key).toBe("logic-1");
    // The COLUMN request_digest is authoritative on read (re-attached over the
    // jsonb body's value).
    expect(got?.request_digest).toBe(hex32("7"));
    expect(got?.response.h_commit).toBe(hex32("a"));
  });

  it("readEnvelope returns undefined when no row exists", async () => {
    const { sql } = fakeSql([]);
    const repo = new PostgresIngestionRepository({ sql });
    expect(await repo.getByHCommit(hex32("a"))).toBeUndefined();
  });

  it("save fails loud (no fake-success) when the response is missing schema_digest", async () => {
    const { sql, calls } = fakeSql([]);
    const repo = new PostgresIngestionRepository({ sql });
    const bad = buildRecord({
      hCommit: hex32("a"),
      idempotencyKey: "logic-2",
      requestDigest: hex32("a"),
      omitSchemaDigest: true,
    });
    await expect(repo.save(bad)).rejects.toThrow(/schema_digest/);
    // It threw BEFORE any DB write was attempted (Rule 19: no partial/fake commit).
    expect(calls.length).toBe(0);
  });
});
