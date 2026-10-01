import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import type { OperationId } from "../types/operation-ids.js";
import { ROUTE_SCOPE_REQUIREMENTS, type ApiScope } from "../types/scopes.js";
import type { PartnerPrincipal } from "../types/auth.js";

export function requiredScopeForOperation(operationId: OperationId): ApiScope | undefined {
  return ROUTE_SCOPE_REQUIREMENTS[operationId];
}

export function assertPartnerScope(operationId: OperationId, principal: PartnerPrincipal, correlationId = "scope"): void {
  const required = requiredScopeForOperation(operationId);
  if (!required) return;
  if (!principal.scopes.has(required)) {
    throw new HttpProblem(
      problemFromCode("AUTH_FORBIDDEN", correlationId, {
        detail: `Partner key lacks required scope ${required}.`,
        safe_refs: { partner_id: principal.partner_id },
      }),
    );
  }
}

export function createScopePreHandler(operationId: OperationId): preHandlerHookHandler {
  return (request: FastifyRequest, _reply: FastifyReply, done): void => {
    const principal = request.partnerPrincipal;
    if (!principal) {
      done(new HttpProblem(
        problemFromCode("AUTH_UNAUTHENTICATED", request.id, {
          detail: "Partner principal missing before scope enforcement.",
        }),
      ));
      return;
    }
    try {
      assertPartnerScope(operationId, principal, request.id);
      done();
    } catch (error) {
      done(error as Error);
    }
  };
}
