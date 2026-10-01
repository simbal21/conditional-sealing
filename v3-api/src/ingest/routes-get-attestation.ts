import type { FastifyInstance, FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";
import { Type } from "@sinclair/typebox";
import { randomUUID } from "node:crypto";

import { HttpProblem, problemFromCode, throwProblem } from "../errors/index.js";
import { RouteRegistry } from "../openapi/scaffold.js";
import { buildG4EndpointAttestation } from "../g4/index.js";
import type { G3Choice, G4Phase, Hex32 } from "../h-commit/index.js";
import { isHex32 } from "../h-commit/index.js";
import type { IngestionDependencies, PdaInspectionForIngest } from "./routes-create-mode-a.js";

// Security-audit-2026-06-02 F-3: the query schema is now bound to the Fastify
// route (below) with `additionalProperties: false` so unknown query keys and
// malformed hex are rejected at the edge instead of coerced.
export const G4EndpointAttestationQuerySchema = Type.Object(
  {
    pda_id: Type.String({ minLength: 1 }),
    authorizationIdCandidate: Type.String({ pattern: "^0x[0-9a-fA-F]{64}$" }),
    preflight_context_digest: Type.String({ pattern: "^0x[0-9a-fA-F]{64}$" }),
    commit_block_number: Type.Integer({ minimum: 0 }),
    commit_block_hash: Type.String({ pattern: "^0x[0-9a-fA-F]{64}$" }),
    partner_id: Type.String({ minLength: 1 }),
    pda_version: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);

export interface G4EndpointAttestationQuery {
  readonly pda_id: string;
  readonly authorizationIdCandidate: string;
  readonly preflight_context_digest: string;
  readonly commit_block_number: number | string;
  readonly commit_block_hash: string;
  readonly partner_id?: string;
  readonly pda_version?: string;
}

function sendProblem(reply: FastifyReply, error: HttpProblem): void {
  reply.status(error.body.status).type("application/problem+json").send(error.body);
}

/**
 * Security-audit-2026-06-02 F-3: reject malformed hex (400) instead of the
 * prior fail-open zero-hash coercion. A zero-bound attestation silently
 * masked client bugs and produced artifacts whose bindings did not match the
 * caller's intended commit.
 */
function requireHex32(value: string, field: string, correlationId: string): Hex32 {
  if (!isHex32(value)) {
    throwProblem("REQUEST_MALFORMED", correlationId, {
      detail: `${field} must be a 32-byte hex string`,
      retryable: false,
    });
  }
  return value;
}

export async function getG4EndpointAttestation(
  query: G4EndpointAttestationQuery,
  dependencies: Pick<IngestionDependencies, "inspectPda">,
  context: { readonly partnerId: string; readonly correlationId: string },
): Promise<ReturnType<typeof buildG4EndpointAttestation>> {
  if (!query.partner_id) {
    throwProblem("REQUEST_MALFORMED", context.correlationId, {
      detail: "partner_id query parameter is required",
      retryable: false,
    });
  }
  // The attestation is scoped to the authenticated partner. A caller may not
  // mint an attestation for a partner other than itself.
  if (query.partner_id !== context.partnerId) {
    throwProblem("AUTH_FORBIDDEN", context.correlationId, {
      detail: "partner_id does not match the authenticated partner credential",
      safe_refs: { partner_id: context.partnerId },
      retryable: false,
    });
  }
  const commitBlockNumber = Number(query.commit_block_number);
  if (!Number.isInteger(commitBlockNumber) || commitBlockNumber < 0) {
    throwProblem("REQUEST_MALFORMED", context.correlationId, {
      detail: "commit_block_number must be a non-negative integer",
      retryable: false,
    });
  }
  const pdaVersion = query.pda_version ?? "1";
  const pda: PdaInspectionForIngest = await dependencies.inspectPda({
    pda_id: query.pda_id,
    partner_id: context.partnerId,
    pda_version: pdaVersion,
  });
  return buildG4EndpointAttestation({
    pda_id: pda.pda_id,
    pda_root: pda.pda_root,
    g3_choice: pda.g3_choice as G3Choice,
    g4_phase: pda.g4_phase as G4Phase,
    authorizationIdCandidate: requireHex32(
      query.authorizationIdCandidate,
      "authorizationIdCandidate",
      context.correlationId,
    ),
    preflight_context_digest: requireHex32(
      query.preflight_context_digest,
      "preflight_context_digest",
      context.correlationId,
    ),
    commit_block_number: commitBlockNumber,
    commit_block_hash: requireHex32(query.commit_block_hash, "commit_block_hash", context.correlationId),
  });
}

export function registerGetG4EndpointAttestationRoute(
  app: FastifyInstance,
  dependencies: Pick<IngestionDependencies, "inspectPda">,
  routeRegistry = new RouteRegistry(),
  // Security-audit-2026-06-02 F-3: partner-HMAC preHandler is REQUIRED. The
  // composition root supplies `createPartnerHmacPreHandler(...)`. The route
  // also hard-fails (401) if no partnerPrincipal is attached, so a misconfigured
  // mount cannot expose an unauthenticated attestation-minting surface.
  options: { readonly preHandler?: preHandlerHookHandler | preHandlerHookHandler[] } = {},
): RouteRegistry {
  routeRegistry.register({
    operationId: "getG4EndpointAttestation",
    method: "GET",
    url: "/v1/g4/attestation",
    requestSchema: G4EndpointAttestationQuerySchema,
  });

  app.get(
    "/v1/g4/attestation",
    {
      schema: { querystring: G4EndpointAttestationQuerySchema },
      ...(options.preHandler ? { preHandler: options.preHandler } : {}),
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const correlationId = request.id ?? randomUUID();
      const principal = request.partnerPrincipal;
      if (!principal) {
        sendProblem(
          reply,
          new HttpProblem(
            problemFromCode("AUTH_UNAUTHENTICATED", correlationId, {
              detail: "G4 attestation requires an authenticated partner credential.",
            }),
          ),
        );
        return;
      }
      const query = request.query as G4EndpointAttestationQuery;
      try {
        reply.send(
          await getG4EndpointAttestation(query, dependencies, {
            partnerId: principal.partner_id,
            correlationId,
          }),
        );
      } catch (error) {
        if (error instanceof HttpProblem) {
          sendProblem(reply, error);
          return;
        }
        throw error;
      }
    },
  );
  return routeRegistry;
}
