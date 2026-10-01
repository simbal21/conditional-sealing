import type { FastifyInstance } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import { getSubjectEscrowRecord, requireSubjectPrincipal, type SubjectRouteContext } from "./routes-list-escrows.js";

export function getSubjectVaultBlob(context: SubjectRouteContext, user_id: string, h_commit: string): Record<string, unknown> {
  const record = context.store.vaultBlobs.get(`${user_id}:${h_commit}`);
  if (!record) {
    throw new HttpProblem(
      problemFromCode("VAULT_UNAVAILABLE", "subject_vault", {
        detail: "Subject vault object is unavailable.",
        safe_refs: { h_commit },
        statusOverride: 404,
      }),
    );
  }
  return record;
}

export function registerGetSubjectVaultBlobRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.get<{ Params: { h_commit: string } }>(
    "/v1/subjects/me/escrows/:h_commit/vault-blob",
    { preHandler: context.preHandlers?.("getSubjectVaultBlob") },
    async (request) => {
      const principal = requireSubjectPrincipal(request);
      getSubjectEscrowRecord(context, principal, request.params.h_commit);
      return getSubjectVaultBlob(context, principal.user_id, request.params.h_commit);
    },
  );
}
