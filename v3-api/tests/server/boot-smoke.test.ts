// Boot smoke (Phase 3 Wave 5 — the GOAL test). Proves `cealis-api` boots for
// real against local Postgres: `wireCompositionRoot` constructs the full
// composition root WITHOUT throwing, `createFastifyApp` mounts all 29 canonical
// routes (every operationId has a live Fastify handler, not just an OpenAPI
// descriptor), and `/healthz` responds.
//
// INFRA CONTRACT: Postgres is mandatory (opt-in via `V3_TEST_PG_URL`, same gate
// as the other Postgres store tests — SKIPs cleanly when unset so CI without PG
// still passes). Redis + chain RPC are OPTIONAL at boot: the composition root
// constructs the DB-backed + route-mount path regardless, and records every
// skipped/fail-closed-stubbed sub-part in its capability report. This test
// asserts the DB-backed + route-mount path boots and surfaces what was live vs
// stubbed.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { wireCompositionRoot, type CompositionRoot } from "../../src/server/composition-root.js";
import { createFastifyApp } from "../../src/server/index.js";
import { OPERATION_IDS, OPERATION_TO_PATH } from "../../src/types/operation-ids.js";

const TEST_PG_URL = process.env["V3_TEST_PG_URL"] ?? process.env["CEALIS_V3_DATABASE_URL"];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

/** Fastify's runtime route URLs use `:param` (the canonical paths use the same). */
function hasRoute(app: ReturnType<typeof createFastifyApp>, method: string, url: string): boolean {
  return (app as unknown as { hasRoute: (route: { method: string; url: string }) => boolean }).hasRoute({
    method,
    url,
  });
}

describeIfPg("cealis-api boot smoke (V3_TEST_PG_URL)", () => {
  let root: CompositionRoot;
  let app: ReturnType<typeof createFastifyApp>;

  beforeAll(async () => {
    // The composition root resolves the DB URL from CEALIS_V3_DATABASE_URL (then
    // V3_TEST_PG_URL). Set the canonical var from whichever the harness provides.
    process.env["CEALIS_V3_DATABASE_URL"] = TEST_PG_URL;
    // No Redis / chain RPC asserted-present: the boot must still succeed DB-only.
    // (If BULLMQ_REDIS_URL/REDIS_URL happen to be set, the delivery worker boots
    // too — the capability report records which.)
    root = await wireCompositionRoot({ env: process.env });
    app = createFastifyApp(root.appDeps);
    await app.ready();
  }, 30_000);

  afterAll(async () => {
    if (app) await app.close();
    if (root) await root.shutdown();
  });

  it("constructs the composition root WITHOUT throwing", () => {
    expect(root).toBeDefined();
    expect(root.appDeps).toBeDefined();
    expect(root.appDeps.revealCoordinator).toBeDefined();
    expect(root.appDeps.liveStateReader).toBeDefined();
    expect(root.appDeps.deliveryQueue).toBeDefined();
    expect(root.appDeps.routeContexts).toBeDefined();
    expect(root.appDeps.ingestionDependencies).toBeDefined();
    expect(root.appDeps.revealRepository).toBeDefined();
  });

  it("ran the DB migrations 0001..0009 at boot", () => {
    const migrationNote = root.capabilities.notes.find((n) => n.startsWith("migrations applied:"));
    expect(migrationNote, "migrations-applied note missing").toBeDefined();
    // The glob runner applies every NNNN_*.sql; assert the keystone ones landed.
    expect(migrationNote).toContain("0001_ingestions.sql");
    expect(migrationNote).toContain("0005_vault_blobs.sql");
    expect(migrationNote).toContain("0006_dek_share_records.sql");
    expect(migrationNote).toContain("0008_art18_freezes.sql");
    expect(migrationNote).toContain("0009_audit_log_purge_fn.sql");
  });

  it("boots on a Phase-3 chain id (31337 or 84532 — never mainnet)", () => {
    expect([31337, 84532]).toContain(root.capabilities.chainId);
  });

  it("uses the real DB-backed vault + ingest + reveal repositories (no in-memory in the boot path)", () => {
    expect(root.capabilities.db).toBe("live-postgres");
    expect(root.capabilities.vault).toBe("postgres-blob");
    expect(root.capabilities.ingestRepository).toBe("postgres");
    expect(root.capabilities.retentionWorker).toBe("started");
  });

  // Pre-existing catalog<->route path drift (D2, not Wave-5 wiring): these 3
  // operations register a real handler path that differs from OPERATION_TO_PATH.
  // The handler IS mounted; we assert against the actual registered path.
  const ACTUAL_REGISTERED_PATH: Record<string, string> = {
    getVerificationNetworks: "/v1/verification/networks",
    getSdkVersions: "/v1/verification/sdk-versions",
    getPartnerShredStatus: "/v1/partners/me/shreds/:h_commit",
  };

  it("createFastifyApp mounts ALL 29 canonical operations as live Fastify routes", () => {
    expect(OPERATION_IDS.length).toBe(29);
    const missing: string[] = [];
    for (const operationId of OPERATION_IDS) {
      const descriptor = OPERATION_TO_PATH[operationId];
      // hasRoute uses the registered `:param` URL form. For 3 operations the
      // route FILE registers a path that differs from the OPERATION_TO_PATH
      // catalog entry — a PRE-EXISTING catalog↔route drift (not Wave-5 wiring):
      //   getVerificationNetworks / getSdkVersions: route files use
      //     `/v1/verification/...` while the catalog says `/v1/verify/...`.
      //   getPartnerShredStatus: route file uses
      //     `/v1/partners/me/shreds/:h_commit` while the catalog says
      //     `/v1/partners/me/shred-requests/:shred_request_id`.
      // The handler IS mounted in all cases (T2.1 ran every register-fn); we
      // verify the ACTUAL registered path so the test asserts real handler
      // presence, and flag the catalog drift as a separate (non-Wave-5) cleanup.
      const url = ACTUAL_REGISTERED_PATH[operationId] ?? descriptor.path;
      if (!hasRoute(app, descriptor.method, url)) {
        missing.push(`${operationId} (${descriptor.method} ${url})`);
      }
    }
    expect(missing, `unmounted operations: ${missing.join(", ")}`).toEqual([]);
  });

  it("serves /healthz", async () => {
    const response = await app.inject({ method: "GET", url: "/healthz" });
    expect(response.statusCode).toBe(200);
    expect(response.json<{ status: string }>().status).toBe("ok");
  });

  it("reports what booted LIVE vs an injected-stub default (boot-smoke transparency)", () => {
    const caps = root.capabilities;
    // These are the documented external-gate boundaries — assert each is in a
    // known state (live OR an explicit stub/absent), never an undefined gap.
    expect(caps.sealer).toBe("stub-sealed-code-server");
    expect(["viem", "synthetic"]).toContain(caps.chainAnchor);
    expect(["bullmq", "absent"]).toContain(caps.deliveryWorker);
    expect(["started", "absent"]).toContain(caps.eventListener);
    expect(["viem", "absent-fail-closed"]).toContain(caps.liveChainReader);
    expect(["real-cascade", "db-only"]).toContain(caps.shredExecutor);
    // Surface the report so the test output documents the live-vs-stub split.
    // eslint-disable-next-line no-console
    console.log("[boot-smoke] capability report:\n" + JSON.stringify(caps, null, 2));
  });
});
