// Fastify app factory for the @cealis/v3-api server.
//
// Currently mounted as Fastify HANDLERS (i.e., requests are actually served):
//   - POST /v1/verify/artifact-bundles                (canonical, App. A — via registerVerifyRoutes)
//   - GET  /v1/verification/networks                  (canonical, App. A — via registerVerifyRoutes)
//   - GET  /v1/sdk-versions                           (canonical, App. A — via registerVerifyRoutes)
//   - POST /internal/reveal/initiate                  (INTERNAL-OPERATIONAL — see note below)
//   - GET  /healthz                                   (infrastructure probe)
//
// REGISTERED AS OPENAPI DESCRIPTORS ONLY (not yet Fastify-handled — pending
// repository wiring by R2b worker-2):
//   - GET /reveals/{authorizationId}
//   - GET /reveals/{authorizationId}/combiner-manifest
//   - GET /reveals/{authorizationId}/bundles/{recipient_ref}
//
// The canonical reveal-read GET routes (src/reveal/routes-get-{status,manifest,bundle}.ts)
// today only register OpenAPI RouteDescriptors against a RouteRegistry — they
// do NOT bind handlers onto the FastifyInstance. The business-logic functions
// exist (`getRevealStatus`, etc) but need a RevealArtifactRepository wired in,
// which is R2b worker-2's territory (DB-backed repo + Fastify handler binding).
// The RouteRegistry constructed below is currently DISCARDED after descriptor
// registration; once worker-2's repo lands, the registry's descriptors will
// drive Fastify-handler binding here.
//
// ── Note on POST /internal/reveal/initiate (R2b-1 worker-1 brief) ──
//
// The S2-5 §3 canonical reveal-delivery surface is *event-driven* — chain
// emits RevealAuthorized, off-chain combiner consumes, persists, delivers.
// There is intentionally NO POST endpoint in the canonical 29 operationIds
// (App. A); see src/types/operation-ids.ts line 17 comment "event-driven, no
// POST".
//
// The R2b-1 brief calls for a POST entry point that drives the
// RevealCoordinatorImpl.persistAndDeliver flow. To respect both constraints
// we mount it under `/internal/reveal/initiate` — clearly NOT a canonical
// partner-facing operationId, and we DO NOT register it on the RouteRegistry
// (which is asserted-coverage against OPERATION_IDS at boot). It is a
// Cealis-internal operational/test entry point: the orchestrator's
// event-listener path remains the production-canonical driver of
// processRevealAuthorizedEvent; this endpoint exists so the same flow is
// reachable via a request-driven path (integration tests, internal
// ceremonies, dev/CI smoke tests). Partner clients must not call it.
//
// Production HTTP exposure of /internal/* MUST be blocked at the platform
// edge (Railway / ingress / mTLS allow-list). The Fastify app itself does not
// bind /internal/* behind partner-HMAC because no partner credential should
// suffice — the access policy is platform-level, not application-level.

import Fastify, { type FastifyInstance, type FastifyServerOptions } from "fastify";

import { RouteRegistry } from "../openapi/scaffold.js";
import { registerRevealReadRoutes } from "../reveal/index.js";
import { registerVerifyRoutes, type VerifyRouteContext } from "../verify/index.js";
import { registerInternalRevealInitiateRoute } from "./routes-internal-reveal-initiate.js";
import { HttpProblem } from "../errors/index.js";
import { pinoLogFormatter, sanitize } from "../redaction/index.js";
import type { RevealCoordinatorImpl } from "../reveal/reveal-coordinator-impl.js";
import type { LiveStateReader, RevealCoordinatorPorts, RevealDeliveryQueue } from "../reveal/reveal-coordinator.js";
import { registerIngestRoutes } from "../ingest/index.js";
import { registerSubjectRoutes } from "../subject/index.js";
import { registerPartnerRoutes } from "../partner/index.js";
import { registerVaultRoutes } from "../vault/index.js";
import { registerRevealReadHandlers } from "../reveal/index.js";
import type { IngestionDependencies } from "../ingest/index.js";
import type { CealisRouteContexts } from "./route-contexts.js";
import type { RevealArtifactRepository } from "../bundle/index.js";

/**
 * Security-audit-2026-06-02 F-2: explicit project-level request body cap.
 * `plaintext_payload` is Type.Unknown() by design (opaque KYC blob); the
 * previous default left it bounded only by Fastify's 1 MB fallback. 2 MiB
 * leaves headroom for the structured commit envelope + a modest payload while
 * still rejecting oversized bodies at the edge.
 */
export const DEFAULT_BODY_LIMIT_BYTES = 2 * 1024 * 1024;

/**
 * Security-audit-2026-06-02 F-2 (TS-API-F-01 / TS-API-F-04): the Fastify v5
 * default ajv config silently STRIPS unknown properties (`removeAdditional`)
 * rather than rejecting them, so binding a schema with `additionalProperties:
 * false` did nothing observable — smuggled top-level keys were quietly dropped
 * and the request still succeeded. Setting `removeAdditional: false` makes the
 * `additionalProperties: false` contract actually REJECT (400) unknown keys at
 * the edge. Type coercion is left on so querystring integers still coerce.
 *
 * Apply this to EVERY Fastify instance that mounts request-validated routes
 * (production via `createFastifyApp`, and route-level test harnesses) so schema
 * enforcement is uniform.
 */
export const STRICT_AJV_OPTIONS: FastifyServerOptions["ajv"] = {
  customOptions: { removeAdditional: false },
};

/**
 * Application-level dependencies. The route handler for /internal/reveal/initiate
 * consumes these; the GET routes (status / manifest / bundle) read directly
 * from the repository that the combiner-orchestrator writes to, which is
 * R2b worker-2's territory and not mounted on the app object yet.
 */
export interface CealisApiAppDeps {
  /** The reveal coordinator impl (consumed by /internal/reveal/initiate). */
  readonly revealCoordinator: RevealCoordinatorImpl;
  /** Live state reader for the coordinator's clearGatesAt. */
  readonly liveStateReader: LiveStateReader;
  /** Coordinator ports (anchor + clearGatesAt fn; deliveryQueue is deliberately
   *  NOT here — passed as a parameter to persistAndDeliver). */
  readonly coordinatorPorts: RevealCoordinatorPorts;
  /** Delivery queue. */
  readonly deliveryQueue: RevealDeliveryQueue;
  /**
   * Wave-5 (T2.1) route contexts — when supplied, `createFastifyApp` mounts the
   * full 29-operation surface (ingest + subject + partner + vault + reveal-read).
   * OPTIONAL so existing route-level + redaction tests that only exercise the
   * internal-reveal + verify routes keep working with a minimal deps bag.
   */
  readonly routeContexts?: CealisRouteContexts;
  /** Wave-5 (T2.1) ingestion deps — the G4 ingestion + status + Mode-A routes. */
  readonly ingestionDependencies?: IngestionDependencies;
  /**
   * Wave-5 (T2.1) DB-backed reveal repository for the 3 reveal-read GET handlers
   * (status / manifest / bundle). When absent the GETs stay descriptor-only.
   */
  readonly revealRepository?: RevealArtifactRepository;
  /** Optional verify-route context (server-side structural-only verify). */
  readonly verifyContext?: VerifyRouteContext;
  /** Fastify server options pass-through. */
  readonly fastifyOptions?: FastifyServerOptions;
  /**
   * Optional Pino destination stream. When supplied, log lines are written here
   * WHILE keeping the §10.2 redacting formatter (F-09). Lets the composition
   * root / tests capture egress without dropping redaction. Ignored when the
   * caller overrides the whole logger via `fastifyOptions.logger`.
   */
  readonly logStream?: { write(msg: string): void };
}

/**
 * Construct a fully-wired Fastify app. The factory:
 *   1. Builds the FastifyInstance.
 *   2. Registers the canonical S2-5 reveal-read routes via the existing
 *      RouteRegistry path.
 *   3. Registers the verify routes (server-side structural-only).
 *   4. Registers the internal /internal/reveal/initiate route.
 *   5. Returns the app instance — caller calls .listen() or .inject().
 */
export function createFastifyApp(deps: CealisApiAppDeps): FastifyInstance {
  // Security-audit-2026-06-02 F-2 + F-09 (TS-API-F-09): defaults now install a
  // project-level bodyLimit AND a §10.2 PII-redacting Pino log formatter. The
  // caller may still override via deps.fastifyOptions, but a redacting logger
  // and an explicit body cap are the secure baseline rather than {logger:false}.
  const baseOptions: FastifyServerOptions = {
    bodyLimit: DEFAULT_BODY_LIMIT_BYTES,
    ajv: STRICT_AJV_OPTIONS,
    logger: {
      // pinoLogFormatter routes every log object through `sanitize`, redacting
      // σ / shares / DEK / salts / plaintext / bearer secrets at egress
      // (S2-5 §10.2 lines 1002-1012). Was implemented but never wired.
      formatters: { log: pinoLogFormatter },
      ...(deps.logStream ? { stream: deps.logStream } : {}),
    },
  };
  const app = Fastify({ ...baseOptions, ...(deps.fastifyOptions ?? {}) });

  // Security-audit-2026-06-02 F-09: error bodies are a named §10.2 redaction
  // target and bypass the log formatter, so run problem-detail bodies through
  // `sanitize` before serialization. HttpProblem bodies keep their RFC-7807
  // shape (status preserved); anything else collapses to a sanitized 500.
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof HttpProblem) {
      void reply
        .status(error.body.status)
        .type("application/problem+json")
        .send(sanitize(error.body));
      return;
    }
    // Preserve Fastify's own validation/4xx status codes where present.
    const statusCode =
      typeof (error as { statusCode?: number }).statusCode === "number"
        ? (error as { statusCode: number }).statusCode
        : 500;
    void reply.status(statusCode).type("application/problem+json").send(
      sanitize({
        type: "https://docs.cealis.local/problems/request/malformed",
        title: statusCode >= 500 ? "Internal error" : "Request rejected",
        status: statusCode,
        code: statusCode >= 500 ? "REQUEST.INTERNAL" : "REQUEST.MALFORMED",
        category: "REQUEST",
        detail: error.message,
        correlation_id: request.id,
        retryable: false,
      }),
    );
  });

  // (1) Canonical reveal-read OpenAPI descriptors. NOTE: this only registers
  //     route DESCRIPTORS against the local RouteRegistry — it does NOT bind
  //     Fastify handlers. The registry is asserted-coverage against
  //     OPERATION_IDS by Phase F closeout (assertRegistryCoverage), but the
  //     handler binding step is R2b worker-2 territory (needs the
  //     RevealArtifactRepository wired in). See file-top note.
  const registry = new RouteRegistry();
  registerRevealReadRoutes(registry);
  // (2) Verify routes (Fastify-mounted directly, see verify/index.ts pattern).
  registerVerifyRoutes(app, deps.verifyContext ?? {});
  // (3) Internal route (NOT on the registry — see file-top note).
  registerInternalRevealInitiateRoute(app, {
    revealCoordinator: deps.revealCoordinator,
    liveStateReader: deps.liveStateReader,
    coordinatorPorts: deps.coordinatorPorts,
    deliveryQueue: deps.deliveryQueue,
  });

  // (4) Wave-5 (T2.1) — mount the full canonical 29-operation surface when the
  //     composition root supplied the route contexts + ingestion deps. The
  //     register-fns bind Fastify HANDLERS (not just OpenAPI descriptors), so
  //     after this step every operationId has a live route. Each group owns its
  //     own URL prefix so there is no path collision with the verify / internal
  //     routes mounted above.
  if (deps.ingestionDependencies !== undefined) {
    // §2 G4 ingestion: getG4EndpointAttestation + createModeAIngestion + getIngestionStatus.
    registerIngestRoutes(app, deps.ingestionDependencies);
  }
  if (deps.routeContexts !== undefined) {
    // §6 subject (WebAuthn challenge/verify, sessions, escrows, vault-blob,
    //    audit, retention, shred-request, pre-σ payload/confirmations).
    registerSubjectRoutes(app, deps.routeContexts.subject);
    // §5 partner (pdas, onboarding-links, escrow/reveal/obligation/shred status,
    //    shred-request).
    registerPartnerRoutes(app, deps.routeContexts.partner);
    // §8 vault retention.
    registerVaultRoutes(app, deps.routeContexts.vault);
  }
  if (deps.revealRepository !== undefined) {
    // §3 reveal-read (status / delivery-manifest / artifact-bundle) — bind the
    //    Fastify handlers from the DB-backed repository the combiner writes to.
    registerRevealReadHandlers(app, deps.revealRepository);
  }

  // Health probe (no operationId — pure infra).
  app.get("/healthz", async () => ({ status: "ok" }));

  return app;
}
