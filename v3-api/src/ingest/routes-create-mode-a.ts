import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { Type } from "@sinclair/typebox";
import { randomUUID } from "node:crypto";

import { HttpProblem, throwProblem } from "../errors/index.js";
import type { OperationalClass, TrustTier } from "../types/index.js";
import { RouteRegistry } from "../openapi/scaffold.js";
import type { ChainAnchorClient, IngestionAnchorResult } from "../chain-anchor/index.js";
import { SyntheticChainAnchorClient, anchorIngestionWithRetry } from "../chain-anchor/index.js";
import {
  buildG4EndpointAttestation,
  type AttestationPreflight,
  enforceG4PhasePolicy,
  PHASE_1_TRUST_STATEMENT,
  verifyAttestationPreflightOrThrow,
} from "../g4/index.js";
import {
  bytesFromPayload,
  constructHCommitArtifacts,
  isHex32,
  jcsDigestHex32,
  payloadDigestHex32,
  type G3Choice,
  type G4Phase,
  type HCommitArtifacts,
  type Hex32,
  type PayloadCanonicalization,
} from "../h-commit/index.js";

const Hex32Schema = Type.String({ pattern: "^0x[0-9a-fA-F]{64}$" });
const RegistrySnapshotRefSchema = Type.Object(
  {
    registry_name: Type.String(),
    chain_id: Type.Integer(),
    registry_address: Type.String(),
    checked_block: Type.Integer({ minimum: 0 }),
    checked_block_hash: Hex32Schema,
    lookup_key: Type.Optional(Type.String()),
    entry_digest: Hex32Schema,
    proof_ref: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);
const VerificationCheckResultSchema = Type.Object(
  {
    status: Type.Union([Type.Literal("pass"), Type.Literal("fail")]),
    checked_block: Type.Integer({ minimum: 0 }),
    checked_block_hash: Hex32Schema,
    code: Type.Optional(Type.String()),
    safe_refs: Type.Optional(Type.Record(Type.String(), Type.Union([Type.String(), Type.Number(), Type.Boolean()]))),
  },
  { additionalProperties: false },
);
const AttestationVerificationChecksSchema = Type.Object(
  {
    lit_assignment: VerificationCheckResultSchema,
    lit_dcap: VerificationCheckResultSchema,
    g3_pubkey: VerificationCheckResultSchema,
    g4_authority: VerificationCheckResultSchema,
  },
  { additionalProperties: false },
);

export const PreflightCommitContextSchema = Type.Object(
  {
    authorizationIdCandidate: Hex32Schema,
    pda_id: Type.String(),
    pda_version: Type.String(),
    partner_id: Type.String(),
    schema_digest: Hex32Schema,
    payload_digest: Hex32Schema,
    payload_canonicalization: Type.Union([
      Type.Literal("jcs_json"),
      Type.Literal("raw_binary"),
      Type.Literal("multipart_file_part"),
    ]),
    pda_root: Hex32Schema,
    g3_choice: Type.Union([Type.Literal("dcipher"), Type.Literal("drand")]),
    g4_phase: Type.Union([Type.Literal(1), Type.Literal(2)]),
    commit_block_number: Type.Integer({ minimum: 0 }),
    commit_block_hash: Hex32Schema,
    block_source: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);

const AttestationPreflightSchema = Type.Object(
  {
    digest: Hex32Schema,
    authorizationIdCandidate: Hex32Schema,
    preflight_context_digest: Hex32Schema,
    commit_block_number: Type.Integer({ minimum: 0 }),
    commit_block_hash: Hex32Schema,
    registry_refs: Type.Array(RegistrySnapshotRefSchema, { minItems: 3 }),
    lit_assignment: Type.Object(
      {
        authorizationId: Hex32Schema,
        assignment_digest: Hex32Schema,
        assigned_operator_id: Type.String(),
        registry_ref: RegistrySnapshotRefSchema,
        assignment_record_ref: Type.Optional(Type.String()),
      },
      { additionalProperties: false },
    ),
    lit_dcap: Type.Object(
      {
        quote_digest: Hex32Schema,
        bound_authorizationId: Hex32Schema,
        bound_preflight_context_digest: Hex32Schema,
        bound_block_hash: Hex32Schema,
        tee_vendor_family: Type.String(),
        measurement: Type.String(),
        user_data_binding_digest: Type.Optional(Hex32Schema),
        registry_ref: RegistrySnapshotRefSchema,
        quote_ref: Type.Optional(Type.String()),
      },
      { additionalProperties: false },
    ),
    g3_pubkey: Type.Object(
      {
        network: Type.Union([Type.Literal("dcipher"), Type.Literal("drand")]),
        pubkey_digest: Hex32Schema,
        registry_ref: RegistrySnapshotRefSchema,
        committee_id: Type.Optional(Type.String()),
        pubkey_ref: Type.Optional(Type.String()),
      },
      { additionalProperties: false },
    ),
    g4_authority: Type.Object(
      {
        phase: Type.Union([Type.Literal(1), Type.Literal(2)]),
        registry_ref: RegistrySnapshotRefSchema,
        phase1: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
        phase2: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
      },
      { additionalProperties: false },
    ),
    verification_checks: AttestationVerificationChecksSchema,
  },
  { additionalProperties: false },
);

export const ModeAIngestionRequestSchema = Type.Object(
  {
    pda_id: Type.String(),
    pda_version: Type.String(),
    partner_id: Type.String(),
    authorizationIdCandidate: Hex32Schema,
    preflight_commit_context: PreflightCommitContextSchema,
    preflight_context_digest: Hex32Schema,
    subject_commitment_inputs: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
    sigma_subject: Type.Optional(Type.String()),
    pre_sigma_session_id: Type.Optional(Type.String()),
    schema_digest: Hex32Schema,
    payload_classification: Type.Record(Type.String(), Type.Unknown()),
    plaintext_payload: Type.Unknown(),
    attestation_preflight: AttestationPreflightSchema,
    client_attestation_digest: Hex32Schema,
    conditional_recipient_confirmations: Type.Optional(Type.Array(Type.String())),
    ingestion_mode: Type.Optional(Type.String()),
    mode: Type.Optional(Type.String()),
    sd_enabled: Type.Optional(Type.Boolean()),
  },
  // additionalProperties: false rejects unknown top-level keys at the schema validator,
  // closing the prototype-pollution + smuggled-field surface. Security-audit-2026-05-14
  // TS-API-F-01 / TS-API-F-04. plaintext_payload remains Type.Unknown() by design
  // (it carries the partner's opaque KYC blob); payload size is bounded by the Fastify
  // body-size limit set at server construction (see server.ts bodyLimit).
  { additionalProperties: false },
);

export const ModeAIngestionResponseSchema = Type.Object(
  {
    api_version: Type.String(),
    commit_version: Type.Literal("0x0302"),
    ingestion_id: Type.String(),
    authorizationId: Hex32Schema,
    h_commit: Hex32Schema,
    pda_id: Type.String(),
    pda_version: Type.String(),
    partner_id: Type.String(),
    vault_ref: Type.String(),
    commit_tx_hash: Type.Optional(Type.String()),
    commit_block: Type.Optional(Type.Integer()),
    endpoint_attestation_digest: Type.Optional(Hex32Schema),
    g3_choice: Type.Optional(Type.Union([Type.Literal("dcipher"), Type.Literal("drand")])),
    g4_phase: Type.Optional(Type.Union([Type.Literal(1), Type.Literal(2)])),
    retention_expires_at: Type.Optional(Type.String()),
    sd_output: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
    status: Type.Union([
      Type.Literal("committed"),
      Type.Literal("pending_chain_anchor"),
      Type.Literal("failed"),
    ]),
    phase_trust_statement: Type.Optional(Type.Literal(PHASE_1_TRUST_STATEMENT)),
  },
  { additionalProperties: true },
);

export interface PreflightCommitContext {
  readonly authorizationIdCandidate: Hex32;
  readonly pda_id: string;
  readonly pda_version: string;
  readonly partner_id: string;
  readonly schema_digest: Hex32;
  readonly payload_digest: Hex32;
  readonly payload_canonicalization: PayloadCanonicalization;
  readonly pda_root: Hex32;
  readonly g3_choice: G3Choice;
  readonly g4_phase: G4Phase;
  readonly commit_block_number: number;
  readonly commit_block_hash: Hex32;
  readonly block_source?: string;
}

export interface ModeAIngestionRequest {
  readonly pda_id: string;
  readonly pda_version: string;
  readonly partner_id: string;
  readonly authorizationIdCandidate: Hex32;
  readonly preflight_commit_context: PreflightCommitContext;
  readonly preflight_context_digest: Hex32;
  readonly subject_commitment_inputs?: Record<string, unknown>;
  readonly sigma_subject?: string;
  readonly pre_sigma_session_id?: string;
  readonly schema_digest: Hex32;
  readonly payload_classification: Record<string, unknown>;
  readonly plaintext_payload: unknown;
  readonly attestation_preflight: AttestationPreflight;
  readonly client_attestation_digest: Hex32;
  readonly conditional_recipient_confirmations?: readonly string[];
  readonly ingestion_mode?: string;
  readonly mode?: string;
  readonly sd_enabled?: boolean;
}

export interface ModeAIngestionResponse {
  readonly api_version: string;
  readonly commit_version: "0x0302";
  readonly ingestion_id: string;
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly pda_id: string;
  readonly pda_version: string;
  readonly partner_id: string;
  readonly vault_ref: string;
  readonly commit_tx_hash?: string;
  readonly commit_block?: number;
  readonly endpoint_attestation_digest?: Hex32;
  readonly g3_choice?: G3Choice;
  readonly g4_phase?: G4Phase;
  readonly retention_expires_at?: string;
  readonly sd_output?: Record<string, unknown>;
  readonly status: "committed" | "pending_chain_anchor" | "failed";
  readonly phase_trust_statement?: typeof PHASE_1_TRUST_STATEMENT;
}

export interface PdaInspectionForIngest {
  readonly pda_id: string;
  readonly pda_version: string;
  readonly partner_id: string;
  readonly pda_root: Hex32;
  readonly schema_digest: Hex32;
  readonly g3_choice: G3Choice;
  readonly g4_phase: G4Phase;
  readonly operational_class: OperationalClass;
  readonly trust_tier: TrustTier;
  readonly retention_seconds: bigint;
  readonly retention_policy_id?: string;
  readonly partner_ready: boolean;
  readonly legal_effect_expected: boolean;
  readonly halted?: boolean;
  readonly halt_reason?: string;
  readonly recipients_root?: Hex32;
  readonly reveal_challenge_window_seconds?: number;
  readonly shred_challenge_window_seconds?: number;
  readonly shred_authority_id?: Hex32;
  readonly conditional_recipients_policy_digest?: Hex32;
  readonly oracle_references_root?: Hex32;
  readonly dsl_version_ref?: Hex32;
  readonly g4_authority_ref?: Hex32;
  readonly shred_authority?: "subject" | "joint" | "operator" | "timelock" | "disabled";
  readonly shred_condition_summary?: string;
}

export interface IngestionRecord {
  readonly request_digest: Hex32;
  readonly idempotency_key: string;
  readonly response: ModeAIngestionResponse;
  readonly retention_status: {
    readonly h_commit: Hex32;
    readonly retention_policy_id?: string;
    readonly retention_expires_at: string;
    readonly shred_authority?: string;
    readonly shred_condition_summary?: string;
  };
}

export interface IngestionRepository {
  // Wave-5 async swap: the in-memory repo resolves synchronously; the Postgres
  // repo (PostgresIngestionRepository / AsyncIngestionRepository) cannot. Both
  // satisfy this `T | Promise<T>` shape, so the 3 call sites below `await` the
  // result uniformly — the sync repo's plain value awaits to itself, the async
  // repo's Promise resolves. No rename, no fork (T1.1 _AssertMethodParity holds).
  getByIdempotencyKey(idempotencyKey: string): IngestionRecord | undefined | Promise<IngestionRecord | undefined>;
  getByHCommit(hCommit: Hex32): IngestionRecord | undefined | Promise<IngestionRecord | undefined>;
  save(record: IngestionRecord): void | Promise<void>;
}

export interface VaultWriter {
  write(input: {
    readonly h_commit: Hex32;
    readonly plaintext: Uint8Array;
    readonly payload_classification: Record<string, unknown>;
  }): Promise<{ readonly vault_ref: string }>;
}

export interface IngestionDependencies {
  readonly inspectPda: (input: {
    readonly pda_id: string;
    readonly partner_id: string;
    readonly pda_version: string;
  }) => Promise<PdaInspectionForIngest> | PdaInspectionForIngest;
  readonly repository?: IngestionRepository;
  readonly vault?: VaultWriter;
  readonly chainAnchor?: ChainAnchorClient;
  readonly now?: () => Date;
  /**
   * GAP-B per-request ingest-context seam. When wired (composition root with a
   * `RealVaultWriter`), the route calls this with the full computed
   * `HCommitArtifacts` + the resolved PDA inspection + the vault ref + retention
   * floor JUST BEFORE `vault.write`, so the writer's `IngestContextResolver` can
   * recompute the identical commit binding the route bound (no re-derivation, no
   * drift). The `SyntheticVaultWriter` path leaves it undefined (no-op).
   */
  readonly registerIngestContext?: (input: IngestContextRegistration) => void;
}

/** What the route hands the GAP-B ingest-context hook before `vault.write`. The
 *  composition root maps this into the `IngestWriteContext` the `RealVaultWriter`
 *  resolves (it holds the full `HCommitArtifacts` the route computed). */
export interface IngestContextRegistration {
  readonly h_commit: Hex32;
  readonly hCommitArtifacts: HCommitArtifacts;
  /** PDA-selected access-structure (FIXED_ONLY / RECIPIENT_K_OF_N) — present on
   *  the extended inspection; the route forwards it when available. */
  readonly accessStructureProfile?: PdaInspectionForIngestExtendedLike["access_structure_profile"];
  readonly retentionPolicyId?: string;
  readonly retentionExpiresAt: string;
  readonly shredAuthority?: "subject" | "joint" | "operator" | "timelock" | "disabled";
  readonly vaultRef: string;
}

/** Structural shape of the extended-inspection fields the route reads for the
 *  GAP-B hook (kept structural to avoid a Wave-3 import in this Wave-5 file). */
interface PdaInspectionForIngestExtendedLike {
  readonly access_structure_profile: unknown;
}

export interface CreateModeAContext {
  readonly correlationId: string;
  readonly idempotencyKey: string;
  readonly apiVersion: string;
  readonly clientAttestationDigestHeader: string;
  readonly authKind: "partner_hmac" | "subject_bearer";
}

export class InMemoryIngestionRepository implements IngestionRepository {
  private readonly byIdempotencyKey = new Map<string, IngestionRecord>();
  private readonly byHCommit = new Map<string, IngestionRecord>();

  getByIdempotencyKey(idempotencyKey: string): IngestionRecord | undefined {
    return this.byIdempotencyKey.get(idempotencyKey);
  }

  getByHCommit(hCommit: Hex32): IngestionRecord | undefined {
    return this.byHCommit.get(hCommit);
  }

  save(record: IngestionRecord): void {
    this.byIdempotencyKey.set(record.idempotency_key, record);
    this.byHCommit.set(record.response.h_commit, record);
  }
}

export const defaultIngestionRepository = new InMemoryIngestionRepository();

class SyntheticVaultWriter implements VaultWriter {
  async write(input: {
    readonly h_commit: Hex32;
    readonly plaintext: Uint8Array;
    readonly payload_classification: Record<string, unknown>;
  }): Promise<{ readonly vault_ref: string }> {
    void input.plaintext;
    void input.payload_classification;
    return { vault_ref: `vault://${input.h_commit}` };
  }
}

function sendProblem(reply: FastifyReply, error: HttpProblem): void {
  reply.status(error.body.status).type("application/problem+json").send(error.body);
}

function isModeBRequest(body: ModeAIngestionRequest): boolean {
  const mode = (body.mode ?? body.ingestion_mode ?? "").toLowerCase();
  return mode === "b" || mode === "mode_b" || mode === "mode_b_reserved";
}

function assertModeAOnly(body: ModeAIngestionRequest, correlationId: string): void {
  if (isModeBRequest(body)) {
    throwProblem("SCHEMA_MODE_B_RESERVED", correlationId, {
      detail: "Mode B is reserved; the live ingestion endpoint accepts Mode A only",
      safe_refs: { pda_id: body.pda_id, partner_id: body.partner_id },
      retryable: false,
    });
  }
}

function ensureHex32(value: string, field: string, correlationId: string): asserts value is Hex32 {
  if (!isHex32(value)) {
    throwProblem("REQUEST_MALFORMED", correlationId, {
      detail: `${field} must be a 32-byte hex string`,
      retryable: false,
    });
  }
}

function retentionExpiry(now: Date, retentionSeconds: bigint): string {
  const millis = BigInt(now.getTime()) + retentionSeconds * 1000n;
  return new Date(Number(millis)).toISOString();
}

function recordDigest(body: ModeAIngestionRequest): Hex32 {
  return jcsDigestHex32({
    pda_id: body.pda_id,
    pda_version: body.pda_version,
    partner_id: body.partner_id,
    authorizationIdCandidate: body.authorizationIdCandidate,
    preflight_context_digest: body.preflight_context_digest,
    schema_digest: body.schema_digest,
    payload_classification: body.payload_classification,
    payload_digest: body.preflight_commit_context.payload_digest,
  });
}

function extractSubjectCommitment(input: ModeAIngestionRequest): Hex32 | undefined {
  const candidate = input.subject_commitment_inputs?.["subject_commitment_v3"];
  return isHex32(candidate) ? candidate : undefined;
}

function assertPdaMatchesRequest(
  pda: PdaInspectionForIngest,
  body: ModeAIngestionRequest,
  correlationId: string,
): void {
  if (
    pda.pda_id !== body.pda_id ||
    pda.pda_version !== body.pda_version ||
    pda.partner_id !== body.partner_id ||
    pda.schema_digest !== body.schema_digest ||
    pda.schema_digest !== body.preflight_commit_context.schema_digest ||
    pda.pda_root !== body.preflight_commit_context.pda_root ||
    pda.g3_choice !== body.preflight_commit_context.g3_choice ||
    pda.g4_phase !== body.preflight_commit_context.g4_phase
  ) {
    throwProblem("SCHEMA_PDA_SCHEMA_MISMATCH", correlationId, {
      detail: "PDA inspection fields did not match request commit metadata",
      safe_refs: { pda_id: body.pda_id, partner_id: body.partner_id },
      retryable: false,
    });
  }
}

function assertPayloadDigestMatches(body: ModeAIngestionRequest, correlationId: string): Uint8Array {
  const canonicalization = body.preflight_commit_context.payload_canonicalization;
  const digest = payloadDigestHex32(body.plaintext_payload, canonicalization);
  if (digest !== body.preflight_commit_context.payload_digest) {
    throwProblem("ATTESTATION_DCAP_INVALID", correlationId, {
      detail: "Plaintext payload digest did not match pre-flight commit context",
      safe_refs: { authorizationId: body.authorizationIdCandidate, pda_id: body.pda_id },
      retryable: false,
    });
  }
  return bytesFromPayload(body.plaintext_payload, canonicalization);
}

function assertPreflightDigestMatches(body: ModeAIngestionRequest, correlationId: string): void {
  const digest = jcsDigestHex32(body.preflight_commit_context);
  if (digest !== body.preflight_context_digest) {
    throwProblem("ATTESTATION_DCAP_INVALID", correlationId, {
      detail: "Server recomputed pre-flight context digest did not match request body",
      safe_refs: { authorizationId: body.authorizationIdCandidate, pda_id: body.pda_id },
      retryable: false,
    });
  }
}

function assertAuthAllowed(
  pda: PdaInspectionForIngest,
  context: CreateModeAContext,
  correlationId: string,
): void {
  if (pda.operational_class === "consumer" && context.authKind === "partner_hmac") {
    throwProblem("AUTH_FORBIDDEN", correlationId, {
      detail: "Consumer PDA rejects partner-HMAC ingestion paths",
      safe_refs: { pda_id: pda.pda_id, partner_id: pda.partner_id },
      retryable: false,
    });
  }
  // M8 wires certificate validation; Phase B only carries the mTLS-required fact.
}

export async function createModeAIngestion(
  body: ModeAIngestionRequest,
  dependencies: IngestionDependencies,
  context: CreateModeAContext,
): Promise<ModeAIngestionResponse> {
  assertModeAOnly(body, context.correlationId);
  ensureHex32(body.authorizationIdCandidate, "authorizationIdCandidate", context.correlationId);
  ensureHex32(body.preflight_context_digest, "preflight_context_digest", context.correlationId);
  ensureHex32(body.schema_digest, "schema_digest", context.correlationId);
  ensureHex32(body.client_attestation_digest, "client_attestation_digest", context.correlationId);

  const repository = dependencies.repository ?? defaultIngestionRepository;
  const requestDigest = recordDigest(body);
  // Wave-5 async swap (call site 1 of 3): await covers both the sync in-memory
  // repo and the async PostgresIngestionRepository.
  const existing = await repository.getByIdempotencyKey(context.idempotencyKey);
  if (existing !== undefined) {
    if (existing.request_digest !== requestDigest) {
      throwProblem("IDEMPOTENCY_KEY_CONFLICT", context.correlationId, {
        detail: "Idempotency-Key replay used divergent ingestion metadata",
        safe_refs: { pda_id: body.pda_id, partner_id: body.partner_id },
        retryable: false,
      });
    }
    return existing.response;
  }

  const pda = await dependencies.inspectPda({
    pda_id: body.pda_id,
    partner_id: body.partner_id,
    pda_version: body.pda_version,
  });
  assertPdaMatchesRequest(pda, body, context.correlationId);
  assertAuthAllowed(pda, context, context.correlationId);
  if (pda.halted === true) {
    throwProblem("GOVERNANCE_G4_REFUSED", context.correlationId, {
      detail: "PDA inspection reported halted state before commit",
      safe_refs: { pda_id: pda.pda_id, partner_id: pda.partner_id },
      retryable: false,
    });
  }
  enforceG4PhasePolicy(
    {
      g4_phase: pda.g4_phase,
      operational_class: pda.operational_class,
      partner_ready: pda.partner_ready,
      legal_effect_expected: pda.legal_effect_expected,
    },
    context.correlationId,
  );

  assertPreflightDigestMatches(body, context.correlationId);
  const plaintext = assertPayloadDigestMatches(body, context.correlationId);
  verifyAttestationPreflightOrThrow(
    body.attestation_preflight as AttestationPreflight,
    {
      authorizationIdCandidate: body.authorizationIdCandidate,
      preflight_context_digest: body.preflight_context_digest,
      commit_block_number: body.preflight_commit_context.commit_block_number,
      commit_block_hash: body.preflight_commit_context.commit_block_hash,
      client_attestation_digest: body.client_attestation_digest,
      header_attestation_digest: context.clientAttestationDigestHeader,
    },
    context.correlationId,
  );

  const hCommit = constructHCommitArtifacts(
    {
      pda_root: pda.pda_root,
      partner_id: pda.partner_id,
      schema_digest: pda.schema_digest,
      g3_choice: pda.g3_choice,
      g4_phase: pda.g4_phase,
      retention_seconds: pda.retention_seconds,
      recipients_root: pda.recipients_root,
      reveal_challenge_window_seconds: pda.reveal_challenge_window_seconds,
      shred_challenge_window_seconds: pda.shred_challenge_window_seconds,
      shred_authority_id: pda.shred_authority_id,
      conditional_recipients_policy_digest: pda.conditional_recipients_policy_digest,
      oracle_references_root: pda.oracle_references_root,
      dsl_version_ref: pda.dsl_version_ref,
      g4_authority_ref: pda.g4_authority_ref,
    },
    {
      authorizationId: body.authorizationIdCandidate,
      subject_commitment_v3: extractSubjectCommitment(body),
      sigma_subject: body.sigma_subject,
      pre_sigma_session_id: body.pre_sigma_session_id,
      endpoint_attestation_digest: body.attestation_preflight.digest,
    },
  );

  // GAP-B: register the full per-request ingest context (the computed
  // HCommitArtifacts + PDA-selected access structure + retention floor + vault
  // ref) so the RealVaultWriter's IngestContextResolver recomputes the IDENTICAL
  // commit binding the route just bound. No-op when the SyntheticVaultWriter path
  // is in use (composition root leaves `registerIngestContext` undefined).
  const ingestVaultRef = `vault://${hCommit.h_commit}`;
  const ingestRetentionExpiresAt = retentionExpiry(
    dependencies.now?.() ?? new Date(),
    pda.retention_seconds,
  );
  const pdaExtended = pda as unknown as {
    readonly access_structure_profile?: unknown;
  };
  dependencies.registerIngestContext?.({
    h_commit: hCommit.h_commit,
    hCommitArtifacts: hCommit,
    ...(pdaExtended.access_structure_profile !== undefined
      ? { accessStructureProfile: pdaExtended.access_structure_profile }
      : {}),
    ...(pda.retention_policy_id !== undefined ? { retentionPolicyId: pda.retention_policy_id } : {}),
    retentionExpiresAt: ingestRetentionExpiresAt,
    ...(pda.shred_authority !== undefined ? { shredAuthority: pda.shred_authority } : {}),
    vaultRef: ingestVaultRef,
  });

  let vaultRef: string;
  try {
    vaultRef = (await (dependencies.vault ?? new SyntheticVaultWriter()).write({
      h_commit: hCommit.h_commit,
      plaintext,
      payload_classification: body.payload_classification,
    })).vault_ref;
  } catch {
    throwProblem("VAULT_UNAVAILABLE", context.correlationId, {
      detail: "Vault write failed before chain anchor",
      safe_refs: { authorizationId: hCommit.authorizationId, h_commit: hCommit.h_commit },
      retryable: true,
    });
  }

  const anchor: IngestionAnchorResult = await anchorIngestionWithRetry({
    client: dependencies.chainAnchor ?? new SyntheticChainAnchorClient(),
    correlationId: context.correlationId,
    anchor: {
      authorizationId: hCommit.authorizationId,
      h_commit: hCommit.h_commit,
      pda_root: pda.pda_root,
      commit_block_hash: body.preflight_commit_context.commit_block_hash,
      idempotency_key: context.idempotencyKey,
    },
  });

  const now = dependencies.now?.() ?? new Date();
  const retentionExpiresAt = retentionExpiry(now, pda.retention_seconds);
  const response: ModeAIngestionResponse = {
    api_version: context.apiVersion,
    commit_version: "0x0302",
    ingestion_id: randomUUID(),
    authorizationId: hCommit.authorizationId,
    h_commit: hCommit.h_commit,
    pda_id: pda.pda_id,
    pda_version: pda.pda_version,
    partner_id: pda.partner_id,
    vault_ref: vaultRef,
    commit_tx_hash: anchor.commit_tx_hash,
    commit_block: anchor.commit_block,
    endpoint_attestation_digest: body.attestation_preflight.digest,
    g3_choice: pda.g3_choice,
    g4_phase: pda.g4_phase,
    retention_expires_at: retentionExpiresAt,
    sd_output: { status: "not_configured" },
    status: "committed",
    ...(pda.g4_phase === 1 ? { phase_trust_statement: PHASE_1_TRUST_STATEMENT } : {}),
  };

  // Wave-5 async swap (call site 2 of 3).
  await repository.save({
    idempotency_key: context.idempotencyKey,
    request_digest: requestDigest,
    response,
    retention_status: {
      h_commit: response.h_commit,
      retention_policy_id: pda.retention_policy_id,
      retention_expires_at: retentionExpiresAt,
      shred_authority: pda.shred_authority,
      shred_condition_summary: pda.shred_condition_summary,
    },
  });
  return response;
}

function headerValue(value: string | string[] | undefined, fallback: string): string {
  if (Array.isArray(value)) return value[0] ?? fallback;
  return value ?? fallback;
}

function authKindFromRequest(request: FastifyRequest): "partner_hmac" | "subject_bearer" {
  const authorization = headerValue(request.headers.authorization, "");
  return authorization.toLowerCase().startsWith("bearer ") ? "subject_bearer" : "partner_hmac";
}

export function registerCreateModeAIngestionRoute(
  app: FastifyInstance,
  dependencies: IngestionDependencies,
  routeRegistry = new RouteRegistry(),
): RouteRegistry {
  routeRegistry.register({
    operationId: "createModeAIngestion",
    method: "POST",
    url: "/v1/ingestions",
    requestSchema: ModeAIngestionRequestSchema,
    responseSchema: { 201: ModeAIngestionResponseSchema },
  });

  app.post(
    "/v1/ingestions",
    {
      // Security-audit-2026-06-02 F-2 (TS-API-F-01 / TS-API-F-04): bind the
      // TypeBox schema as the Fastify route body schema so the validator
      // actually enforces `additionalProperties: false` + types/required at the
      // edge. Previously the schema lived only on the discarded RouteRegistry
      // (OpenAPI descriptor) and Fastify performed ZERO body validation.
      schema: { body: ModeAIngestionRequestSchema },
    },
    async (
      request: FastifyRequest<{ Body: ModeAIngestionRequest }>,
      reply: FastifyReply,
    ) => {
      const correlationId = headerValue(request.headers["x-correlation-id"], randomUUID());
      try {
        const response = await createModeAIngestion(request.body, dependencies, {
          correlationId,
          idempotencyKey: headerValue(request.headers["idempotency-key"], ""),
          apiVersion: headerValue(request.headers["cealis-api-version"], "1.0-draft"),
          clientAttestationDigestHeader: headerValue(
            request.headers["x-cealis-client-attestation-digest"],
            "",
          ),
          authKind: authKindFromRequest(request),
        });
        reply.status(201).send(response);
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

export function buildSyntheticAttestationForRequest(
  body: Pick<
    ModeAIngestionRequest,
    | "pda_id"
    | "authorizationIdCandidate"
    | "preflight_context_digest"
    | "preflight_commit_context"
  >,
): ReturnType<typeof buildG4EndpointAttestation> {
  return buildG4EndpointAttestation({
    pda_id: body.pda_id,
    pda_root: body.preflight_commit_context.pda_root,
    g3_choice: body.preflight_commit_context.g3_choice,
    g4_phase: body.preflight_commit_context.g4_phase,
    authorizationIdCandidate: body.authorizationIdCandidate,
    preflight_context_digest: body.preflight_context_digest,
    commit_block_number: body.preflight_commit_context.commit_block_number,
    commit_block_hash: body.preflight_commit_context.commit_block_hash,
  });
}
