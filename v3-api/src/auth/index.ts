import type { PartnerPrincipal, SubjectPrincipal } from "../types/auth.js";

declare module "fastify" {
  interface FastifyRequest {
    partnerPrincipal?: PartnerPrincipal;
    subjectPrincipal?: SubjectPrincipal;
    rawBodyBytes?: Uint8Array;
  }
}

export * from "./canonical-request.js";
export * from "./nonce-store.js";
export * from "./hmac-middleware.js";
export * from "./bearer-middleware.js";
export * from "./scope-enforce.js";
export * from "./idempotency-middleware.js";
export * from "./rate-limit-middleware.js";
// R2b LBU mock→real swap: Postgres impls of the three in-memory stores.
// Either pair (InMemory* / Postgres*) is selectable at the composition root
// based on V3_DB_URL env presence.
export * from "./postgres-nonce-store.js";
export * from "./postgres-idempotency-store.js";
export * from "./postgres-rate-limit-store.js";
