// Route-context assembly (Phase 3 Wave 5, plan T2.1) — the single place the
// composition root builds the four route contexts `createFastifyApp` mounts:
//
//   SubjectRouteContext   (+ shred executor + resolver wiring, T4.2)
//   PartnerRouteContext   (+ shred executor + resolver wiring, T4.2)
//   VaultRouteContext
//   IngestionDependencies (assembled in composition-root, passed through here)
//
// Each route module owns its own context-defining file (Wave-5 single-owner
// discipline); this file does NOT edit them — it composes their factory outputs
// and threads the shred-executor seam through the OPTIONAL context extensions
// (SubjectShredRouteContext / PartnerShredRouteContext) the route files already
// declared. When the executor is present the shred routes run the real cascade;
// when absent they keep the in-memory `requested`-status behaviour.
//
// TrustTier mapping: the v3-api runtime uses `tier_a|tier_b|tier_c`; the
// configurator uses `A|B|C`. The single translation is `mapTrustTier`
// (ingest/pda-inspector.ts) — re-exported here so there is exactly one mapper.
//
// V3 isolation: no @cealis/shared, no V1 packages, no V1 env vars.

import {
  createDefaultSubjectRouteContext,
  type SubjectRouteContext,
} from "../subject/index.js";
import { createPartnerStatusStore } from "../partner/index.js";
import { createVaultRouteContext, type VaultRouteContext } from "../vault/index.js";

import {
  normalizeShredAuthority,
  type ShredExecutionRequest,
  type ShredExecutor,
} from "../shred/shred-executor.js";
import type {
  SubjectShredExecutionResolver,
  SubjectShredRouteContext,
} from "../subject/routes-create-shred-request.js";
import type {
  PartnerShredExecutionResolver,
  PartnerShredRouteContext,
} from "../partner/routes-create-shred-request.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

// Re-export the single TrustTier mapper so consumers don't re-derive it.
export { mapTrustTier } from "../ingest/pda-inspector.js";

/** The four assembled route contexts the app factory mounts. */
export interface CealisRouteContexts {
  readonly subject: SubjectShredRouteContext;
  readonly partner: PartnerShredRouteContext;
  readonly vault: VaultRouteContext;
}

export interface BuildRouteContextsOptions {
  /** The real crypto-shred executor (T4.2). Threaded into both shred routes. */
  readonly shredExecutor: ShredExecutor;
  /**
   * Whether the executor's chain leg is fully wired (RPC + key). When false the
   * resolvers are still wired (the route falls back to the in-memory `requested`
   * status because the executor would fail-closed at the chain step) — we only
   * attach the executor+resolver when the cascade can actually complete, so a
   * shred request DB-only boot returns `requested` rather than a loud 503.
   */
  readonly shredExecutorReady: boolean;
}

const ZERO_HEX32 = `0x${"0".repeat(64)}` as Hex32;

/** Coerce an unknown to a 0x-prefixed 32-byte hex, else the zero sentinel. */
function asHex32(value: unknown): Hex32 {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value) ? (value as Hex32) : ZERO_HEX32;
}

/**
 * Subject shred resolver — turns the authenticated escrow record into a fully
 * PDA-derived `ShredExecutionRequest`. The vault ref + pda_root + reason digest
 * are read from the escrow record (PLATFORM PRINCIPLE: nothing hardcoded). The
 * record's capitalized `shred_authority` is normalized to the vault enum.
 */
const subjectShredResolver: SubjectShredExecutionResolver = {
  resolve(input): ShredExecutionRequest {
    const record = input.record as unknown as Record<string, unknown>;
    return {
      hCommit: input.h_commit as Hex32,
      shredAuthority: normalizeShredAuthority(input.record.shred_authority),
      vaultRef: typeof record["vault_ref"] === "string" ? (record["vault_ref"] as string) : `vault://${input.h_commit}`,
      pdaRoot: asHex32(record["pda_root"]),
      reasonDigest: asHex32(input.body.request_reason_ref),
      actorRef: input.user_id,
      ...(input.body.request_reason_ref !== undefined ? { requestReasonRef: input.body.request_reason_ref } : {}),
      pdaId: input.record.pda_id,
    };
  },
};

/** Partner shred resolver — symmetric to the subject one, keyed off the partner
 *  escrow + PDA record. */
const partnerShredResolver: PartnerShredExecutionResolver = {
  resolve(input): ShredExecutionRequest {
    const escrow = input.escrow;
    return {
      hCommit: input.h_commit as Hex32,
      shredAuthority: normalizeShredAuthority(input.pda.shred_authority),
      vaultRef: typeof escrow["vault_ref"] === "string" ? (escrow["vault_ref"] as string) : `vault://${input.h_commit}`,
      pdaRoot: asHex32(escrow["pda_root"]),
      reasonDigest: asHex32(input.body.request_reason_ref),
      actorRef: input.partner_id,
      ...(input.body.request_reason_ref !== undefined ? { requestReasonRef: input.body.request_reason_ref } : {}),
      partnerId: input.partner_id,
      pdaId: input.pda.pda_id,
    };
  },
};

/**
 * Assemble the four route contexts. The subject + partner contexts carry the
 * read-side stores (escrow / pda / vault-blob listings) the GET routes serve,
 * PLUS the shred executor + resolver when the cascade is wired so the shred POST
 * routes run the real crypto-shred (T4.2). The base read stores remain the
 * route-facing seam the GET routes already consume — the runtime write-path
 * repos (Postgres ingestion / reveal / vault) are separate and live on the
 * IngestionDependencies + the combiner deps, not these read stores.
 */
export function buildRouteContexts(options: BuildRouteContextsOptions): CealisRouteContexts {
  const baseSubject: SubjectRouteContext = createDefaultSubjectRouteContext();
  const subject: SubjectShredRouteContext = options.shredExecutorReady
    ? { ...baseSubject, shredExecutor: options.shredExecutor, resolveShredRequest: subjectShredResolver }
    : baseSubject;

  const partner: PartnerShredRouteContext = options.shredExecutorReady
    ? {
        store: createPartnerStatusStore(),
        shredExecutor: options.shredExecutor,
        resolveShredRequest: partnerShredResolver,
      }
    : { store: createPartnerStatusStore() };

  const vault: VaultRouteContext = createVaultRouteContext();

  return { subject, partner, vault };
}
