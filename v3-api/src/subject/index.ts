import type { FastifyInstance } from "fastify";
import { InMemoryPreSigmaConfirmationStore, PreSigmaSessionBinder } from "../pre-sigma/index.js";
import { InMemorySubjectSessionStore, InMemoryWebAuthnChallengeStore } from "../webauthn/index.js";
import { registerCreateSubjectShredRequestRoute } from "./routes-create-shred-request.js";
import { registerExportSubjectAuditRoute } from "./routes-export-audit.js";
import { registerGetSubjectEscrowRoute } from "./routes-get-escrow.js";
import { registerGetSubjectRetentionRoute } from "./routes-get-retention.js";
import { registerGetSubjectVaultBlobRoute } from "./routes-get-vault-blob.js";
import {
  createSubjectApiStore,
  registerListSubjectEscrowsRoute,
  type SubjectRouteContext,
} from "./routes-list-escrows.js";
import { registerPreSigmaConfirmationsRoute } from "./routes-pre-sigma-confirmations.js";
import { registerPreSigmaPayloadRoute } from "./routes-pre-sigma-payload.js";
import { registerSubjectSessionRevokeRoute } from "./routes-session-revoke.js";
import { registerSubjectWebAuthnChallengeRoute } from "./routes-webauthn-challenge.js";
import { registerSubjectWebAuthnVerifyRoute } from "./routes-webauthn-verify.js";

export * from "./routes-list-escrows.js";
export * from "./routes-get-escrow.js";
export * from "./routes-get-vault-blob.js";
export * from "./routes-export-audit.js";
export * from "./routes-get-retention.js";
export * from "./routes-create-shred-request.js";
export * from "./routes-session-revoke.js";
export * from "./routes-webauthn-challenge.js";
export * from "./routes-webauthn-verify.js";
export * from "./routes-pre-sigma-payload.js";
export * from "./routes-pre-sigma-confirmations.js";

export function createDefaultSubjectRouteContext(): SubjectRouteContext {
  const binder = new PreSigmaSessionBinder();
  return {
    store: createSubjectApiStore(),
    sessions: new InMemorySubjectSessionStore(),
    challenges: new InMemoryWebAuthnChallengeStore(),
    preSigmaBinder: binder,
    confirmations: new InMemoryPreSigmaConfirmationStore(binder),
  };
}

export function registerSubjectRoutes(app: FastifyInstance, context: SubjectRouteContext): void {
  registerSubjectWebAuthnChallengeRoute(app, context);
  registerSubjectWebAuthnVerifyRoute(app, context);
  registerSubjectSessionRevokeRoute(app, context);
  registerListSubjectEscrowsRoute(app, context);
  registerGetSubjectEscrowRoute(app, context);
  registerGetSubjectVaultBlobRoute(app, context);
  registerExportSubjectAuditRoute(app, context);
  registerGetSubjectRetentionRoute(app, context);
  registerCreateSubjectShredRequestRoute(app, context);
  registerPreSigmaPayloadRoute(app, context);
  registerPreSigmaConfirmationsRoute(app, context);
}
