// PostgresRevealArtifactRepository tests.
//
// Two layers:
//   1. LOGIC (always runs, no infra) — a shared lifecycle spec asserted against
//      InMemoryRevealArtifactRepository. This pins the contract the Postgres impl
//      must match (upsertStatus → putManifest → putBundle status-flip-to-finalized,
//      artifact_bundles reconstruction, scope isolation). If the contract drifts,
//      this fails without a database.
//   2. LIVE Postgres (opt-in via V3_TEST_PG_URL; SKIPs cleanly when unset) — the
//      SAME spec run against the real DB-backed repo + Postgres-specific guarantees
//      the in-memory impl cannot prove: persistence across repo instances (the row
//      survives a fresh client), jsonb manifest/bundle round-trip byte-for-byte,
//      and the sentinel-ref guard.
//
// The reveals migration (0002) does NOT yet create the `manifest`/`bundle` jsonb
// columns the Drizzle schema-extension declares (cross-cluster gap — flagged for
// the T0.1 migration owner). The live suite ALTERs them in IF NOT EXISTS so the
// test is self-contained against the migration-as-shipped until 0002 backfills it.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import type { Sql } from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  InMemoryRevealArtifactRepository,
  type PersistedBundleRecord,
  type RevealArtifactRepository,
  type RevealStatusRecord,
} from "../../src/bundle/persist.js";
import {
  PostgresRevealArtifactRepository,
  STATUS_HEADER_RECIPIENT_REF,
} from "../../src/bundle/postgres-reveal-repository.js";
import type { CombinerManifest } from "../../src/types/combiner-manifest.js";
import type {
  Hex32,
  RevealArtifactBundle,
  SigmaBlock,
} from "../../src/types/reveal-artifact-bundle.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const MIGRATIONS_DIR = join(__dirname, "..", "..", "src", "db", "migrations");

const TEST_PG_URL = process.env["V3_TEST_PG_URL"];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

// --- fixtures --------------------------------------------------------------

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}

function sigmaBlock(phase: 1 | 2 = 2): SigmaBlock {
  return {
    sigma_subject: "0x1234",
    sigma_lit: { sigma: "0x11", authority_ref: hex(11), public_after_reveal: true },
    sigma_g3: { sigma: "0x22", authority_ref: hex(12), variant: "dcipher", public_after_reveal: true },
    sigma_g4: { sigma: "0x33", authority_ref: hex(13), phase, public_after_reveal: true },
    sigma_conditional: [],
  };
}

function bundleFixture(opts: {
  authorizationId: Hex32;
  hCommit: Hex32;
  recipientRef: string;
  g4Phase?: 1 | 2;
  challengeWindowExpiredAt?: string;
}): RevealArtifactBundle {
  const challenge = opts.challengeWindowExpiredAt ?? "2026-05-11T00:01:00.000Z";
  return {
    bundle_version: "s2-5.1",
    canonicalization: {
      format: "JCS",
      rfc: "RFC8785",
      hash: "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))",
    },
    authorization: {
      authorizationId: opts.authorizationId,
      h_commit: opts.hCommit,
      commit_version: "0x0302",
      authorization_block: 200,
      authorization_block_hash: hex(3),
      authorization_timestamp: "2026-05-11T00:00:00.000Z",
      conditionRef: hex(4),
      challenge_window_seconds: 60,
      challenge_window_expired_at: challenge,
      finalized_at: "2026-05-11T00:02:00.000Z",
    },
    pda: {
      pda_id: "11111111-1111-4111-8111-111111111111",
      pda_version: "fixture",
      pda_root: hex(5),
      trust_tier: "tier_b",
      operational_class: "regulated",
    },
    recipient: {
      recipient_ref: opts.recipientRef,
      recipient_pubkey_id: "pubkey-a",
      schema_selector_digest: hex(6),
    },
    plaintext: {
      schema_selector_digest: hex(6),
      schema_digest: hex(7),
      content_encoding: "application/json",
      fields: { legal_name: "Alice" },
      field_hashes: { legal_name: hex(8) },
    },
    issuer_attestation: { status: "not_configured" },
    provenance: { status: "not_configured" },
    sigma_block: sigmaBlock(opts.g4Phase ?? 2),
    chain_proofs: {
      chain_id: 8453,
      condition_engine_address: "0x0000000000000000000000000000000000000001",
      reveal_authorized_emitter: "0x0000000000000000000000000000000000000001",
      reveal_authorized_event_signature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
      reveal_authorized_topics: [hex(1), hex(2)],
      receipt_proof: { proof_type: "mock_receipt", block_number: 200, block_hash: hex(3), log_index: 0 },
      commit_tx_hash: hex(20),
      commit_block: 100,
      commit_block_hash: hex(21),
      reveal_authorized_tx_hash: hex(22),
      reveal_authorized_log_index: 0,
      reveal_authorized_block: 200,
      reveal_authorized_block_hash: hex(3),
      base_finality_confirmations: 32,
    },
    registry_snapshots: { authorization_block: 200, authorization_block_hash: hex(3), registry_contracts: {} },
    shred_state: { h_commit: opts.hCommit, shred_state: "not_shredded" },
    sd_refs: { status: "not_configured" },
    verification: { artifact_bundle_digest: hex(9), verifier_version: "test" },
    pii_statement: "recipient_filtered_plaintext_after_valid_reveal",
  };
}

function manifestFixture(authorizationId: Hex32, hCommit: Hex32): CombinerManifest {
  return {
    authorizationId,
    h_commit: hCommit,
    authorization_block: 200,
    block_hash: hex(3),
    pda_id: "11111111-1111-4111-8111-111111111111",
    g3_choice: "dcipher",
    g4_phase: 2,
    gate_endpoints: { g2: "lit", g3: "dcipher" },
    registry_snapshot_refs: {},
    recipient_policy: { recipients: ["recipient-a"] },
    combiner_execution_context: "audited_process_memory",
    delegation_allowed: false,
    recipient_control_requirement: "recipient_local",
    tee_hsm_required: false,
    risk_statement_required: false,
    policy_evidence_refs: [],
  };
}

function statusRecord(
  authorizationId: Hex32,
  hCommit: Hex32,
  overrides: Partial<RevealStatusRecord> = {},
): RevealStatusRecord {
  return {
    authorizationId,
    h_commit: hCommit,
    status: "authorized",
    g4_phase: 2,
    challenge_window_expired_at: "2026-05-11T00:01:00.000Z",
    ...overrides,
  };
}

function bundleRecord(opts: {
  authorizationId: Hex32;
  hCommit: Hex32;
  recipientRef: string;
}): PersistedBundleRecord {
  const bundle = bundleFixture(opts);
  return {
    authorizationId: opts.authorizationId,
    h_commit: opts.hCommit,
    recipient_ref: opts.recipientRef,
    bundle_digest: hex(99),
    bundle_storage_ref: `vault://reveal-artifacts/${opts.authorizationId}/${opts.recipientRef}`,
    status: "finalized",
    finalized_at: "2026-05-11T00:02:00.000Z",
    bundle,
  };
}

// --- shared lifecycle spec --------------------------------------------------

/**
 * The contract every RevealArtifactRepository impl must satisfy. Run against the
 * in-memory reference impl (no infra) AND the Postgres impl (live DB). `freshAuth`
 * mints a unique authorizationId per test so live-DB runs don't collide across
 * parallel vitest files sharing one database.
 */
function lifecycleSpec(
  label: string,
  makeRepo: () => RevealArtifactRepository | Promise<RevealArtifactRepository>,
  freshAuth: () => { authorizationId: Hex32; hCommit: Hex32 },
): void {
  describe(label, () => {
    it("returns undefined for an unknown authorization", async () => {
      const repo = await makeRepo();
      const { authorizationId } = freshAuth();
      expect(await repo.getStatus(authorizationId)).toBeUndefined();
      expect(await repo.getManifest(authorizationId)).toBeUndefined();
      expect(await repo.getBundle(authorizationId, "recipient-a")).toBeUndefined();
      expect(await repo.listBundles(authorizationId)).toEqual([]);
    });

    it("upsertStatus → getStatus round-trips the authorization-level status", async () => {
      const repo = await makeRepo();
      const { authorizationId, hCommit } = freshAuth();
      await repo.upsertStatus(statusRecord(authorizationId, hCommit, { status: "authorized" }));
      const got = await repo.getStatus(authorizationId);
      expect(got?.status).toBe("authorized");
      expect(got?.g4_phase).toBe(2);
      expect(got?.h_commit).toBe(hCommit);
      expect(got?.challenge_window_expired_at).toBe("2026-05-11T00:01:00.000Z");
    });

    it("upsertStatus overwrites the prior status (refusal path)", async () => {
      const repo = await makeRepo();
      const { authorizationId, hCommit } = freshAuth();
      await repo.upsertStatus(statusRecord(authorizationId, hCommit));
      await repo.upsertStatus(
        statusRecord(authorizationId, hCommit, {
          status: "refused",
          refusal: { reason_code: "0x01", reason_label: "legal_compel" },
        }),
      );
      const got = await repo.getStatus(authorizationId);
      expect(got?.status).toBe("refused");
      expect(got?.refusal).toEqual({ reason_code: "0x01", reason_label: "legal_compel" });
    });

    it("putManifest → getManifest round-trips the manifest", async () => {
      const repo = await makeRepo();
      const { authorizationId, hCommit } = freshAuth();
      await repo.upsertStatus(statusRecord(authorizationId, hCommit));
      const manifest = manifestFixture(authorizationId, hCommit);
      await repo.putManifest(authorizationId, manifest);
      expect(await repo.getManifest(authorizationId)).toEqual(manifest);
    });

    it("putManifest works even if it lands before upsertStatus", async () => {
      const repo = await makeRepo();
      const { authorizationId, hCommit } = freshAuth();
      const manifest = manifestFixture(authorizationId, hCommit);
      await repo.putManifest(authorizationId, manifest);
      expect(await repo.getManifest(authorizationId)).toEqual(manifest);
    });

    it("putBundle persists the bundle AND flips status to finalized", async () => {
      const repo = await makeRepo();
      const { authorizationId, hCommit } = freshAuth();
      await repo.upsertStatus(statusRecord(authorizationId, hCommit, { status: "authorized" }));
      const rec = bundleRecord({ authorizationId, hCommit, recipientRef: "recipient-a" });
      await repo.putBundle(rec);

      const got = await repo.getBundle(authorizationId, "recipient-a");
      expect(got?.bundle).toEqual(rec.bundle);
      expect(got?.bundle_digest).toBe(rec.bundle_digest);
      expect(got?.status).toBe("finalized");

      const status = await repo.getStatus(authorizationId);
      expect(status?.status).toBe("finalized");
      expect(status?.artifact_bundles).toEqual([
        {
          recipient_ref: "recipient-a",
          bundle_digest: rec.bundle_digest,
          bundle_storage_ref: rec.bundle_storage_ref,
          status: "finalized",
        },
      ]);
    });

    it("multi-recipient: listBundles + artifact_bundles cover every recipient", async () => {
      const repo = await makeRepo();
      const { authorizationId, hCommit } = freshAuth();
      await repo.upsertStatus(statusRecord(authorizationId, hCommit));
      await repo.putBundle(bundleRecord({ authorizationId, hCommit, recipientRef: "recipient-a" }));
      await repo.putBundle(bundleRecord({ authorizationId, hCommit, recipientRef: "recipient-b" }));

      const list = await repo.listBundles(authorizationId);
      expect(list.map((b) => b.recipient_ref).sort()).toEqual(["recipient-a", "recipient-b"]);

      const status = await repo.getStatus(authorizationId);
      expect(status?.artifact_bundles?.map((b) => b.recipient_ref).sort()).toEqual([
        "recipient-a",
        "recipient-b",
      ]);
    });

    it("putBundle is idempotent on the same recipient_ref (re-deliver updates, no dup)", async () => {
      const repo = await makeRepo();
      const { authorizationId, hCommit } = freshAuth();
      await repo.upsertStatus(statusRecord(authorizationId, hCommit));
      await repo.putBundle(bundleRecord({ authorizationId, hCommit, recipientRef: "recipient-a" }));
      await repo.putBundle(bundleRecord({ authorizationId, hCommit, recipientRef: "recipient-a" }));
      const list = await repo.listBundles(authorizationId);
      expect(list).toHaveLength(1);
      const status = await repo.getStatus(authorizationId);
      expect(status?.artifact_bundles).toHaveLength(1);
    });

    it("isolates authorizations (a bundle under one auth is invisible to another)", async () => {
      const repo = await makeRepo();
      const a = freshAuth();
      const b = freshAuth();
      await repo.upsertStatus(statusRecord(a.authorizationId, a.hCommit));
      await repo.putBundle(
        bundleRecord({ authorizationId: a.authorizationId, hCommit: a.hCommit, recipientRef: "recipient-a" }),
      );
      expect(await repo.listBundles(b.authorizationId)).toEqual([]);
      expect(await repo.getBundle(b.authorizationId, "recipient-a")).toBeUndefined();
    });
  });
}

// --- 1. logic spec against the in-memory reference impl (no infra) ----------

let inMemAuthCounter = 0x1000;
lifecycleSpec(
  "RevealArtifactRepository contract — InMemory (logic, no DB)",
  () => new InMemoryRevealArtifactRepository(),
  () => {
    const n = inMemAuthCounter++;
    return { authorizationId: hex(n), hCommit: hex(n + 0x10000) };
  },
);

// --- 2. live Postgres round-trip (opt-in V3_TEST_PG_URL) --------------------

describeIfPg("PostgresRevealArtifactRepository (V3_TEST_PG_URL)", () => {
  let sql: Sql;
  let P: number; // per-suite numeric prefix to avoid cross-file collisions

  beforeAll(async () => {
    if (!TEST_PG_URL) return;
    sql = postgres(TEST_PG_URL, { max: 4, idle_timeout: 5, onnotice: () => {} });
    // 0002 creates the `reveals` table. The `manifest`/`bundle` jsonb columns the
    // schema-extension declares are NOT in 0002 yet (cross-cluster gap — see file
    // header); ALTER them in defensively so the test is self-contained. Serialize
    // the DDL with an advisory lock (parallel vitest workers race in pg_type).
    const m2 = readFileSync(join(MIGRATIONS_DIR, "0002_reveals.sql"), "utf-8");
    const LOCK_KEY = 8675313;
    await sql`SELECT pg_advisory_lock(${LOCK_KEY})`;
    try {
      await sql.unsafe(m2);
      await sql.unsafe(
        "ALTER TABLE reveals ADD COLUMN IF NOT EXISTS manifest jsonb; " +
          "ALTER TABLE reveals ADD COLUMN IF NOT EXISTS bundle jsonb;",
      );
    } finally {
      await sql`SELECT pg_advisory_unlock(${LOCK_KEY})`;
    }
    P = (process.pid % 0x10000) * 0x10000 + Math.floor(Math.random() * 0x10000);
  });

  afterAll(async () => {
    if (!sql) return;
    // Drop only this suite's rows (namespaced by the numeric auth-id prefix range).
    await sql`DELETE FROM reveals WHERE authorization_id LIKE ${"0x" + P.toString(16).padStart(8, "0") + "%"}`;
    await sql.end({ timeout: 5 });
  });

  let liveAuthCounter = 0;
  const freshAuth = () => {
    // authorizationId = 0x<P padded to 8 hex><counter padded to 56 hex> → unique
    // 32-byte hex, prefixed by this suite's range so afterAll's LIKE matches.
    const n = liveAuthCounter++;
    const authHex = ("0x" + P.toString(16).padStart(8, "0") + n.toString(16).padStart(56, "0")) as Hex32;
    const commitHex = ("0x" + P.toString(16).padStart(8, "0") + (n + 1).toString(16).padStart(56, "0")) as Hex32;
    return { authorizationId: authHex, hCommit: commitHex };
  };

  // Run the SAME contract spec against the real DB-backed repo.
  lifecycleSpec(
    "contract parity",
    () => new PostgresRevealArtifactRepository({ sql }),
    freshAuth,
  );

  // Postgres-specific guarantees the in-memory impl cannot prove.

  it("persists across repo instances (the row survives a fresh repo)", async () => {
    const { authorizationId, hCommit } = freshAuth();
    const writer = new PostgresRevealArtifactRepository({ sql });
    await writer.upsertStatus(statusRecord(authorizationId, hCommit));
    await writer.putManifest(authorizationId, manifestFixture(authorizationId, hCommit));
    await writer.putBundle(bundleRecord({ authorizationId, hCommit, recipientRef: "recipient-a" }));

    // A brand-new repo over the same DB sees the persisted state.
    const reader = new PostgresRevealArtifactRepository({ sql });
    const status = await reader.getStatus(authorizationId);
    expect(status?.status).toBe("finalized");
    expect(status?.artifact_bundles).toHaveLength(1);
    const bundle = await reader.getBundle(authorizationId, "recipient-a");
    expect(bundle?.bundle.recipient.recipient_ref).toBe("recipient-a");
  });

  it("round-trips the manifest + bundle jsonb byte-for-byte", async () => {
    const { authorizationId, hCommit } = freshAuth();
    const repo = new PostgresRevealArtifactRepository({ sql });
    const manifest = manifestFixture(authorizationId, hCommit);
    const rec = bundleRecord({ authorizationId, hCommit, recipientRef: "recipient-a" });
    await repo.upsertStatus(statusRecord(authorizationId, hCommit));
    await repo.putManifest(authorizationId, manifest);
    await repo.putBundle(rec);

    expect(await repo.getManifest(authorizationId)).toEqual(manifest);
    const got = await repo.getBundle(authorizationId, "recipient-a");
    expect(got?.bundle).toEqual(rec.bundle);
  });

  it("preserves g4_phase=1 from the bundle's sigma_g4 on putBundle", async () => {
    const { authorizationId, hCommit } = freshAuth();
    const repo = new PostgresRevealArtifactRepository({ sql });
    await repo.upsertStatus(statusRecord(authorizationId, hCommit, { g4_phase: 1 }));
    const bundle = bundleFixture({ authorizationId, hCommit, recipientRef: "recipient-a", g4Phase: 1 });
    await repo.putBundle({
      authorizationId,
      h_commit: hCommit,
      recipient_ref: "recipient-a",
      bundle_digest: hex(99),
      bundle_storage_ref: "vault://x",
      status: "finalized",
      finalized_at: "2026-05-11T00:02:00.000Z",
      bundle,
    });
    const status = await repo.getStatus(authorizationId);
    expect(status?.g4_phase).toBe(1);
  });

  it("rejects putBundle on the reserved status-header recipient_ref", async () => {
    const { authorizationId, hCommit } = freshAuth();
    const repo = new PostgresRevealArtifactRepository({ sql });
    await expect(
      repo.putBundle(bundleRecord({ authorizationId, hCommit, recipientRef: STATUS_HEADER_RECIPIENT_REF })),
    ).rejects.toThrow(/reserved/i);
  });

  it("never exposes the status-header sentinel row as a bundle", async () => {
    const { authorizationId, hCommit } = freshAuth();
    const repo = new PostgresRevealArtifactRepository({ sql });
    await repo.upsertStatus(statusRecord(authorizationId, hCommit));
    await repo.putBundle(bundleRecord({ authorizationId, hCommit, recipientRef: "recipient-a" }));
    // The sentinel row exists in the table but must never surface via the bundle API.
    expect(await repo.getBundle(authorizationId, STATUS_HEADER_RECIPIENT_REF)).toBeUndefined();
    const list = await repo.listBundles(authorizationId);
    expect(list.map((b) => b.recipient_ref)).not.toContain(STATUS_HEADER_RECIPIENT_REF);
  });
});
