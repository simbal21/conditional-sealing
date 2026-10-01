import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { Type } from "@sinclair/typebox";
import { randomUUID } from "node:crypto";

import { HttpProblem, throwProblem } from "../errors/index.js";
import { RouteRegistry } from "../openapi/scaffold.js";
import type { Hex32 } from "../h-commit/index.js";
import { isHex32 } from "../h-commit/index.js";
import {
  defaultIngestionRepository,
  type IngestionRepository,
} from "./routes-create-mode-a.js";

export const EscrowStatusSchema = Type.Object(
  {
    h_commit: Type.String({ pattern: "^0x[0-9a-fA-F]{64}$" }),
    status: Type.String(),
    pda_id: Type.String(),
    g4_phase: Type.Union([Type.Literal(1), Type.Literal(2)]),
    vault_ref: Type.Optional(Type.String()),
    retention_expires_at: Type.Optional(Type.String()),
    sd_status: Type.Optional(Type.String()),
    retention: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
  },
  { additionalProperties: true },
);

export interface IngestionStatus {
  readonly h_commit: Hex32;
  readonly status: string;
  readonly pda_id: string;
  readonly g4_phase: 1 | 2;
  readonly vault_ref?: string;
  readonly retention_expires_at?: string;
  readonly sd_status?: string;
  readonly retention?: Record<string, unknown>;
}

function sendProblem(reply: FastifyReply, error: HttpProblem): void {
  reply.status(error.body.status).type("application/problem+json").send(error.body);
}

export async function getIngestionStatus(
  hCommit: string,
  repository: IngestionRepository = defaultIngestionRepository,
  correlationId = randomUUID(),
): Promise<IngestionStatus> {
  if (!isHex32(hCommit)) {
    throwProblem("REQUEST_MALFORMED", correlationId, {
      detail: "h_commit path parameter must be a 32-byte hex string",
      retryable: false,
    });
  }
  // Wave-5 async swap (call site 3 of 3): await covers both the sync in-memory
  // repo and the async PostgresIngestionRepository.
  const record = await repository.getByHCommit(hCommit);
  if (record === undefined) {
    throwProblem("REQUEST_MALFORMED", correlationId, {
      detail: "No ingestion record found for h_commit",
      safe_refs: { h_commit: hCommit },
      retryable: false,
    });
  }
  return {
    h_commit: hCommit,
    status: record.response.status,
    pda_id: record.response.pda_id,
    g4_phase: record.response.g4_phase ?? 2,
    vault_ref: record.response.vault_ref,
    retention_expires_at: record.response.retention_expires_at,
    sd_status: record.response.sd_output?.["status"] === "not_configured" ? "not_configured" : "configured",
    retention: record.retention_status,
  };
}

export function registerGetIngestionStatusRoute(
  app: FastifyInstance,
  repository: IngestionRepository = defaultIngestionRepository,
  routeRegistry = new RouteRegistry(),
): RouteRegistry {
  routeRegistry.register({
    operationId: "getIngestionStatus",
    method: "GET",
    url: "/v1/ingestions/:h_commit",
    responseSchema: { 200: EscrowStatusSchema },
  });
  app.get(
    "/v1/ingestions/:h_commit",
    async (
      request: FastifyRequest<{ Params: { h_commit: string } }>,
      reply: FastifyReply,
    ) => {
      const correlationId = randomUUID();
      try {
        reply.send(await getIngestionStatus(request.params.h_commit, repository, correlationId));
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

