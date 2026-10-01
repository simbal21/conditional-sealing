import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { ChainAnchorClient, IngestionAnchorInput, IngestionAnchorResult } from "../../src/chain-anchor/index.js";
import {
  InMemoryIngestionRepository,
  registerIngestRoutes,
  type IngestionDependencies,
  type PdaInspectionForIngest,
} from "../../src/ingest/index.js";
import { loadCanonicalOpenApi, RouteRegistry } from "../../src/openapi/scaffold.js";
import { createPartnerStatusStore, registerPartnerRoutes } from "../../src/partner/index.js";
import { registerRevealReadRoutes } from "../../src/reveal/index.js";
import { createDefaultSubjectRouteContext, registerSubjectRoutes } from "../../src/subject/index.js";
import type { OperationId } from "../../src/types/index.js";
import { OPERATION_IDS } from "../../src/types/index.js";
import { createVaultRouteContext, registerVaultRoutes } from "../../src/vault/index.js";
import { registerVerifyRoutes } from "../../src/verify/index.js";

type AuthKind = "partner_hmac" | "partner_hmac_or_subject_bearer" | "subject_bearer" | "public";

interface CanonicalRoute {
  readonly operationId: OperationId;
  readonly method: "GET" | "POST" | "DELETE";
  readonly path: string;
  readonly auth: AuthKind;
}

describe("OpenAPI runtime cross-check", () => {
  it("keeps canonical.yaml, RouteRegistry, Fastify routes, and auth shape aligned", async () => {
    const canonicalRoutes = canonicalRouteMap();
    const app = Fastify();
    const registry = registerIngestRoutes(app, ingestionDependencies(), new RouteRegistry());
    registerRevealReadRoutes(registry);

    registerPartnerRoutes(app, { store: createPartnerStatusStore(), preHandlers: () => [] });
    registerSubjectRoutes(app, createDefaultSubjectRouteContext());
    registerVaultRoutes(app, createVaultRouteContext());
    registerVerifyRoutes(app);
    await app.ready();

    const registryRoutes = new Map<OperationId, { method: string; path: string }>();
    for (const route of registry.list()) {
      registryRoutes.set(route.operationId, {
        method: route.method,
        path: normalizeRuntimePath(route.url),
      });
    }

    for (const operationId of OPERATION_IDS) {
      const canonical = canonicalRoutes.get(operationId);
      expect(canonical, `canonical.yaml missing ${operationId}`).toBeDefined();
      expect(canonical!.auth, `${operationId} auth scheme drift`).toBe(expectedAuth(operationId));

      const registryRoute = registryRoutes.get(operationId);
      if (registryRoute !== undefined) {
        expect(registryRoute, `${operationId} registry drift`).toEqual({
          method: canonical!.method,
          path: canonical!.path,
        });
        continue;
      }

      expect(hasRoute(app, canonical!.method, canonical!.path), `${operationId} route missing at ${canonical!.path}`).toBe(true);
    }

    const registeredOnly = [...registryRoutes.keys()].filter((operationId) => !canonicalRoutes.has(operationId));
    expect(registeredOnly).toEqual([]);
  });
});

class MockAnchor implements ChainAnchorClient {
  async anchor(input: IngestionAnchorInput, attempt: number): Promise<IngestionAnchorResult> {
    return {
      commit_tx_hash: input.h_commit,
      commit_block: 12_345 + attempt,
      commit_block_hash: input.commit_block_hash,
      attempts: attempt,
    };
  }
}

function ingestionDependencies(): IngestionDependencies {
  return {
    repository: new InMemoryIngestionRepository(),
    inspectPda: () => pda(),
    chainAnchor: new MockAnchor(),
    vault: {
      async write(input) {
        return { vault_ref: `mock-vault://${input.h_commit}` };
      },
    },
    now: () => new Date("2026-05-11T00:00:00.000Z"),
  };
}

function pda(): PdaInspectionForIngest {
  return {
    pda_id: "pda_demo",
    pda_version: "1",
    partner_id: "partner_demo",
    pda_root: hex(1),
    schema_digest: hex(2),
    g3_choice: "dcipher",
    g4_phase: 2,
    operational_class: "b2b_partner",
    trust_tier: "tier_b",
    retention_seconds: 94_608_000n,
    retention_policy_id: "obligation_plus_3y",
    partner_ready: true,
    legal_effect_expected: false,
    recipients_root: hex(3),
    shred_authority: "joint",
    shred_condition_summary: "fixture shred condition with mandatory guardrail",
  };
}

function canonicalRouteMap(): ReadonlyMap<OperationId, CanonicalRoute> {
  const doc = loadCanonicalOpenApi();
  const routes = new Map<OperationId, CanonicalRoute>();
  for (const [path, methods] of Object.entries(doc.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (!isOperation(operation)) continue;
      routes.set(operation.operationId, {
        operationId: operation.operationId,
        method: method.toUpperCase() as CanonicalRoute["method"],
        path: normalizeRuntimePath(path),
        auth: classifySecurity(operation.security),
      });
    }
  }
  return routes;
}

function isOperation(value: unknown): value is { operationId: OperationId; security?: readonly Record<string, unknown>[] } {
  if (value === null || typeof value !== "object") return false;
  const operationId = (value as { operationId?: unknown }).operationId;
  return typeof operationId === "string" && (OPERATION_IDS as readonly string[]).includes(operationId);
}

function classifySecurity(security: readonly Record<string, unknown>[] | undefined): AuthKind {
  if (security === undefined || security.length === 0) return "public";
  const names = new Set(security.flatMap((requirement) => Object.keys(requirement)));
  const hasPartner = [...names].some((name) => name.startsWith("PartnerHmac"));
  const hasSubject = names.has("SubjectBearer");
  if (hasPartner && hasSubject) return "partner_hmac_or_subject_bearer";
  if (hasPartner) return "partner_hmac";
  if (hasSubject) return "subject_bearer";
  return "public";
}

function expectedAuth(operationId: OperationId): AuthKind {
  if (
    operationId === "getG4EndpointAttestation" ||
    operationId === "createModeAIngestion" ||
    operationId === "getIngestionStatus" ||
    operationId === "getRevealStatus" ||
    operationId === "getCombinerManifest" ||
    operationId === "getRevealArtifactBundle" ||
    operationId === "getVaultRetention"
  ) {
    return "partner_hmac_or_subject_bearer";
  }
  if (
    operationId === "listPartnerPdas" ||
    operationId === "getPartnerPda" ||
    operationId === "createOnboardingLink" ||
    operationId === "getPartnerEscrowStatus" ||
    operationId === "createPartnerShredRequest" ||
    operationId === "getPartnerRevealStatus" ||
    operationId === "getPartnerObligationStatus" ||
    operationId === "getPartnerShredStatus"
  ) {
    return "partner_hmac";
  }
  if (
    operationId === "revokeSubjectSession" ||
    operationId === "listSubjectEscrows" ||
    operationId === "getSubjectEscrowStatus" ||
    operationId === "getSubjectVaultBlob" ||
    operationId === "exportSubjectAuditLog" ||
    operationId === "getSubjectRetention" ||
    operationId === "createSubjectShredRequest"
  ) {
    return "subject_bearer";
  }
  return "public";
}

function normalizeRuntimePath(path: string): string {
  const withPrefix = path.startsWith("/v1/") ? path : `/v1${path}`;
  return withPrefix.replaceAll(/\{([^}]+)\}/g, ":$1");
}

function hasRoute(app: ReturnType<typeof Fastify>, method: string, url: string): boolean {
  return (app as unknown as { hasRoute: (route: { method: string; url: string }) => boolean }).hasRoute({ method, url });
}

function hex(n: number): `0x${string}` {
  return `0x${n.toString(16).padStart(64, "0")}`;
}
