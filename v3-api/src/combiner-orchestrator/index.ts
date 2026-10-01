import type { WebhookEnvelope } from "../types/webhook-events.js";
import type {
  ArtifactSdRefs,
  ArtifactShredState,
  ChainProofs,
  Hex32,
  IssuerAttestationBlock,
  ProvenanceBlock,
  RegistrySnapshots,
  RevealArtifactBundle,
  SigmaBlock,
} from "../types/reveal-artifact-bundle.js";
import type { OperationalClass, TrustTier } from "../types/tier-behavior.js";
import { RefusalCode } from "../types/refusal.js";
import type { CombinerManifest } from "../types/combiner-manifest.js";
import { HttpProblem, problemFromCode } from "../errors/problem.js";
import {
  assembleRevealArtifactBundle,
  bundleStorageRef,
  type M3LowLevelBundleScaffold,
  type RevealArtifactRepository,
} from "../bundle/index.js";
import {
  applyRecipientSelector,
  buildArtifactRecipient,
  type RecipientSelector,
} from "../bundle/per-recipient.js";
import { buildCombinerManifest, type BuildCombinerManifestInput } from "../manifest/index.js";
import type {
  AccessStructureProfile,
  AuthorizationRegistrySnapshot,
  CommitRegistrySnapshot,
} from "../m3-imports.js";

/**
 * Conditional-recipients policy shape the combiner AAD-digest-binds for
 * `RECIPIENT_K_OF_N`. Declared structurally here (rather than importing the
 * `@cealis/v3-custody` named type) so this module compiles against the merged
 * combiner contract regardless of the dependency's build-output freshness; the
 * shape is the authoritative `{ n_conditional, k_conditional }` pair.
 */
export interface ConditionalRecipientsPolicyRef {
  readonly n_conditional: number;
  readonly k_conditional: number;
}
import type { CealisV3Vault, VaultRef } from "../vault/cealis-v3-vault.js";
import type { RevealAuthorizedEvent } from "./event-listener.js";
import {
  runM3CombinerBridge,
  type RunM3CombinerBridgeResult,
} from "./m3-bridge.js";
import type { SigmaGatherer, SigmaGatheringRequest } from "./sigma-gathering.js";
import {
  handleG4Refusal,
  InMemoryG4RefusalStore,
  type G4RefusalEntry,
  type HandleG4RefusalInput,
} from "./refusal-handler.js";

export type CombinerEventBus = {
  emit: (event: WebhookEnvelope<Record<string, unknown>>) => Promise<void> | void;
};

export interface RevealPreconditions {
  readonly challenge_window_closed: boolean;
  readonly shred_state_allows_reveal: boolean;
  readonly registry_deprecation_acceptable: boolean;
  readonly recipient_policy_identified: boolean;
}

/**
 * F-API-1 closure — the combiner input REFERENCE (NOT plaintext).
 *
 * This replaces the old `full_plaintext` field. The reveal path no longer
 * accepts cleartext from the request body. Instead it carries only the
 * *provenance inputs* the cryptographic combiner needs to PRODUCE the
 * plaintext for itself:
 *
 *   - the σ-gathering request (which gates sign for this authorization, per
 *     PDA `g3_choice`) — the gatherer collects gate σ evidence; each gate
 *     supplies per-stanza share material in its σ metadata (`shareHex`);
 *   - the opaque vault ref where the ciphertext + commit binding live (read
 *     via `CealisV3Vault.getBlob`, C1-inseparable);
 *   - the access-structure profile + commit/authorization registry snapshots +
 *     mandatory canonical-address pin + (for K-of-N) the conditional-recipients
 *     policy — the static fields `combineAndDecrypt` requires.
 *
 * `combineAndDecrypt` reconstructs the DEK from the σ-carried shares (which
 * `dealDek` produced at ingest), AEAD-decrypts the vault ciphertext, and
 * returns plaintext. The plaintext's PROVENANCE is therefore the combiner, not
 * the request. There is no field on this type that can supply plaintext
 * directly — the decoupling vuln is unrepresentable.
 *
 * The σ-gatherer and the vault are INJECTED ports on the deps bag; the real
 * network/TEE pieces (Lit V3, dcipher/drand, the G4 TEE, the vault backend)
 * stay vendor-gated behind those ports (Phase-3 plan §6). This reference holds
 * no key material and no plaintext.
 */
export interface CombinerInputReference {
  /** PDA-derived σ-gathering request: which gates sign for this authorization
   *  (G3 routed by PDA `g3_choice` — PLATFORM PRINCIPLE, never hardcoded). */
  readonly sigma_request: SigmaGatheringRequest;
  /** Opaque vault ref for the ciphertext + inseparable commit binding (read
   *  via `vault.getBlob`; C1). No plaintext, no key. */
  readonly vault_ref: VaultRef;
  /** Access-structure profile from `commit_AAD` (FIXED_ONLY / RECIPIENT_1_OF_1
   *  / RECIPIENT_K_OF_N) — drives DEK reconstruction topology. */
  readonly access_structure_profile: AccessStructureProfile;
  /** Commit-block + authorization-block registry snapshots the combiner's
   *  pre-verify pipeline consumes (read live by the chain reader). */
  readonly registry_snapshots: {
    readonly commitSnapshot: CommitRegistrySnapshot;
    readonly authorizationSnapshot: AuthorizationRegistrySnapshot;
  };
  /** MANDATORY canonical-address pin (TS-CRYPTO-F-08): the configured
   *  ConditionEngine address + chainId the combiner asserts against the
   *  compile-time canonical pair. */
  readonly canonical_address_pin: {
    readonly configuredConditionEngine: `0x${string}`;
    readonly chainId: number;
  };
  /** Conditional-recipients policy — REQUIRED for `RECIPIENT_K_OF_N` (the
   *  combiner AAD-digest-binds it), absent for FIXED_ONLY / RECIPIENT_1_OF_1. */
  readonly conditional_recipients_policy?: ConditionalRecipientsPolicyRef;
}

export interface EventDrivenRevealInput {
  readonly event: RevealAuthorizedEvent;
  readonly partner_id: string;
  readonly pda: {
    readonly pda_id: string;
    readonly pda_version: string;
    readonly trust_tier: TrustTier;
    readonly operational_class: OperationalClass;
  };
  readonly g3_choice: "dcipher" | "drand";
  readonly g4_phase: 1 | 2;
  readonly schema_digest: Hex32;
  readonly preconditions: RevealPreconditions;
  /**
   * F-API-1: the combiner input REFERENCE (was `full_plaintext`). The plaintext
   * is produced by `combineAndDecrypt` over gathered σ + vault ciphertext — the
   * request can no longer hand the flow cleartext.
   */
  readonly combiner_input: CombinerInputReference;
  readonly recipient_selectors: readonly RecipientSelector[];
  readonly sigma_block: SigmaBlock;
  readonly chain_proofs: ChainProofs;
  readonly registry_snapshots: RegistrySnapshots;
  readonly shred_state: ArtifactShredState;
  readonly sd_refs: ArtifactSdRefs;
  readonly gate_endpoints: Record<string, unknown>;
  readonly registry_snapshot_refs: Record<string, unknown>;
  readonly recipient_policy: Record<string, unknown>;
  readonly issuer_attestation?: IssuerAttestationBlock;
  readonly provenance?: ProvenanceBlock;
  readonly m3_scaffold?: M3LowLevelBundleScaffold;
  readonly refusal?: Omit<HandleG4RefusalInput, "authorizationId" | "h_commit" | "partner_id" | "pda_id">;
}

export interface EventDrivenRevealResult {
  readonly status: "finalized" | "refused" | "deferred";
  readonly manifest: CombinerManifest;
  readonly bundles: readonly RevealArtifactBundle[];
  readonly failed_recipients: readonly string[];
  readonly refusal?: G4RefusalEntry;
}

/**
 * Strategy for the cryptographic combine+decrypt join (F-API-1). Defaults to
 * the real M3 bridge (`runM3CombinerBridge` → `combineAndDecrypt`). Tests inject
 * a deterministic double behind the SAME shape so they can drive a real
 * decrypt-path round-trip (seal known plaintext, deal shares, gate-double,
 * fake vault) without crossing a vendor boundary.
 */
export type CombineAndDecryptRunner = typeof runM3CombinerBridge;

/** Decode the combiner's plaintext bytes into the field record per-recipient
 *  selection consumes. Default: JSON over UTF-8 (the schema-bound on-wire
 *  encoding). Injectable for non-JSON schemas. */
export type PlaintextDecoder = (plaintext: Uint8Array) => Readonly<Record<string, unknown>>;

const defaultPlaintextDecoder: PlaintextDecoder = (plaintext) => {
  const text = new TextDecoder().decode(plaintext);
  const parsed = JSON.parse(text) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("combiner plaintext did not decode to a JSON object");
  }
  return parsed as Readonly<Record<string, unknown>>;
};

export async function processRevealAuthorizedEvent(
  input: EventDrivenRevealInput,
  deps: {
    readonly repository: RevealArtifactRepository;
    /** Injected σ-gatherer port (real `@cealis/v3-custody` adapters in prod;
     *  deterministic double in tests). Collects gate σ evidence carrying the
     *  per-stanza share material. */
    readonly sigmaGatherer: SigmaGatherer;
    /** Injected vault port (real `CealisV3Vault` in prod; fake in tests).
     *  Yields ciphertext + inseparable commit binding (C1). */
    readonly vault: CealisV3Vault;
    readonly eventBus?: CombinerEventBus;
    readonly refusalStore?: InMemoryG4RefusalStore;
    /** Overridable combine+decrypt runner (default = real M3 bridge). */
    readonly combineAndDecryptRunner?: CombineAndDecryptRunner;
    /** Overridable plaintext decoder (default = JSON/UTF-8). */
    readonly decodePlaintext?: PlaintextDecoder;
    readonly now?: () => Date;
  },
): Promise<EventDrivenRevealResult> {
  assertRevealPreconditions(input.preconditions);
  const now = deps.now?.() ?? new Date();
  const challengeExpiredAt = challengeWindowExpiredAt(input.event);
  const authorization = {
    authorizationId: input.event.authorizationId,
    h_commit: input.event.h_commit,
    commit_version: "0x0302",
    authorization_block: Number(input.event.authorization_block),
    authorization_block_hash: input.event.block_hash ?? input.chain_proofs.reveal_authorized_block_hash,
    authorization_timestamp: timestampToIso(input.event.authorization_timestamp),
    conditionRef: input.event.conditionRef,
    challenge_window_seconds: input.event.challenge_window,
    challenge_window_expired_at: challengeExpiredAt,
    finalized_at: now.toISOString(),
  } satisfies RevealArtifactBundle["authorization"];

  await deps.repository.upsertStatus({
    authorizationId: authorization.authorizationId,
    h_commit: authorization.h_commit,
    status: "authorized",
    g4_phase: input.g4_phase,
    challenge_window_expired_at: challengeExpiredAt,
  });

  const manifest = buildCombinerManifest(manifestInput(input));
  await deps.repository.putManifest(input.event.authorizationId, manifest);

  if (input.refusal !== undefined) {
    const refusal = await handleG4Refusal(
      {
        ...input.refusal,
        authorizationId: input.event.authorizationId,
        h_commit: input.event.h_commit,
        partner_id: input.partner_id,
        pda_id: input.pda.pda_id,
      },
      {
        store: deps.refusalStore ?? new InMemoryG4RefusalStore(),
        eventBus: deps.eventBus,
        now: deps.now,
      },
    );
    if (refusal.blocking) {
      const status = refusal.entry.reason_code === RefusalCode.Art18Restriction ? "deferred" : "refused";
      await deps.repository.upsertStatus({
        authorizationId: authorization.authorizationId,
        h_commit: authorization.h_commit,
        status,
        g4_phase: input.g4_phase,
        challenge_window_expired_at: challengeExpiredAt,
        refusal: {
          reason_code: refusal.entry.reason_code_hex,
          reason_label: refusal.entry.reason_label,
          reason_visibility: refusal.entry.reason_visibility,
          ...(refusal.entry.encrypted_reason_ref === undefined
            ? {}
            : { encrypted_reason_ref: refusal.entry.encrypted_reason_ref }),
        },
      });
      return {
        status,
        manifest,
        bundles: [],
        failed_recipients: [],
        refusal: refusal.entry,
      };
    }
  }

  // ── F-API-1 JOIN: produce plaintext FROM the combiner, not the request ──
  //
  // (1) Gather the per-gate σ evidence (each gate supplies its share material in
  //     σ metadata). (2) Read the vault ciphertext + inseparable commit binding
  //     (C1). (3) Run combineAndDecrypt: reconstruct the DEK from the shares
  //     `dealDek` produced at ingest, AEAD-decrypt → plaintext bytes. (4) Decode
  //     to the field record per-recipient selection consumes. The plaintext's
  //     PROVENANCE is the combiner; the request carries no cleartext.
  let plaintextBytes: Uint8Array | undefined;
  let fullPlaintext: Readonly<Record<string, unknown>> | undefined;
  try {
    const join = await combineAndDecryptFromVault(input, deps);
    plaintextBytes = join.plaintext;
    fullPlaintext = (deps.decodePlaintext ?? defaultPlaintextDecoder)(join.plaintext);
  } catch (error) {
    // Combine/decrypt failed (gather, vault read, or crypto). Fail-CLOSED: no
    // bundle is assembled from an unverified plaintext source. Surface a loud
    // status; zeroize anything transient before rethrowing.
    if (plaintextBytes !== undefined) zeroizeBytes(plaintextBytes);
    await deps.repository.upsertStatus({
      authorizationId: authorization.authorizationId,
      h_commit: authorization.h_commit,
      status: "refused",
      g4_phase: input.g4_phase,
      challenge_window_expired_at: challengeExpiredAt,
    });
    throw error;
  }

  const bundles: RevealArtifactBundle[] = [];
  const failedRecipients: string[] = [];
  try {
  for (const selector of input.recipient_selectors) {
    try {
      const plaintext = applyRecipientSelector({
        fullPlaintext,
        schema_digest: input.schema_digest,
        selector,
        correlation_id: input.event.authorizationId,
      });
      const assembled = assembleRevealArtifactBundle({
        authorization,
        pda: {
          pda_id: input.pda.pda_id,
          pda_version: input.pda.pda_version,
          pda_root: input.event.pda_root,
          trust_tier: input.pda.trust_tier,
          operational_class: input.pda.operational_class,
        },
        recipient: buildArtifactRecipient(selector),
        plaintext,
        issuer_attestation: input.issuer_attestation,
        provenance: input.provenance,
        sigma_block: input.sigma_block,
        chain_proofs: input.chain_proofs,
        registry_snapshots: input.registry_snapshots,
        shred_state: input.shred_state,
        sd_refs: input.sd_refs,
        verification: {
          verifier_version: "s2-5.1-api",
          checks: {
            sdRefs: input.sd_refs.status,
          },
        },
        m3_scaffold: input.m3_scaffold,
      });
      await deps.repository.putBundle({
        authorizationId: authorization.authorizationId,
        h_commit: authorization.h_commit,
        recipient_ref: selector.recipient_ref,
        bundle_digest: assembled.artifact_bundle_digest,
        bundle_storage_ref: bundleStorageRef(authorization.authorizationId, selector.recipient_ref),
        status: "finalized",
        finalized_at: now.toISOString(),
        bundle: assembled.bundle,
      });
      await deps.eventBus?.emit({
        event_id: `${authorization.authorizationId}:${selector.recipient_ref}:finalized`,
        schema_version: "s2-5.1",
        event_type: "reveal.finalized",
        created_at: now.toISOString(),
        partner_id: input.partner_id,
        pda_id: input.pda.pda_id,
        data: {
          authorizationId: authorization.authorizationId,
          h_commit: authorization.h_commit,
          artifact_digest: assembled.artifact_bundle_digest,
          recipient_ref: selector.recipient_ref,
        },
      });
      bundles.push(assembled.bundle);
    } catch (error) {
      if (error instanceof HttpProblem) {
        failedRecipients.push(selector.recipient_ref);
        continue;
      }
      throw error;
    }
  }

  return {
    status: "finalized",
    manifest,
    bundles,
    failed_recipients: failedRecipients,
  };
  } finally {
    // GDPR / crypto hygiene: the full decrypted plaintext exists in this scope
    // only to drive per-recipient selection. Zeroize the raw bytes and drop the
    // decoded-record references the moment bundle assembly is done — only the
    // recipient-FILTERED plaintext lives on in the persisted bundles. The DEK +
    // σ bytes are already zeroized inside `combineAndDecrypt` (its finally).
    zeroizeBytes(plaintextBytes);
    clearRecord(fullPlaintext);
  }
}

function manifestInput(input: EventDrivenRevealInput): BuildCombinerManifestInput {
  return {
    authorizationId: input.event.authorizationId,
    h_commit: input.event.h_commit,
    authorization_block: Number(input.event.authorization_block),
    block_hash: input.event.block_hash ?? input.chain_proofs.reveal_authorized_block_hash,
    pda_id: input.pda.pda_id,
    g3_choice: input.g3_choice,
    g4_phase: input.g4_phase,
    operational_class: input.pda.operational_class,
    gate_endpoints: input.gate_endpoints,
    registry_snapshot_refs: input.registry_snapshot_refs,
    recipient_policy: input.recipient_policy,
  };
}

/**
 * The F-API-1 join, isolated. Gathers σ, reads the vault, and runs the
 * cryptographic combiner. Returns the combiner-PRODUCED plaintext bytes (never
 * touches the request for plaintext). A non-`ok` combiner result is surfaced as
 * an `HttpProblem` so the caller fails closed.
 */
async function combineAndDecryptFromVault(
  input: EventDrivenRevealInput,
  deps: {
    readonly sigmaGatherer: SigmaGatherer;
    readonly vault: CealisV3Vault;
    readonly combineAndDecryptRunner?: CombineAndDecryptRunner;
  },
): Promise<{ readonly plaintext: Uint8Array }> {
  const ref = input.combiner_input;

  // (1) σ gathering — the real network gates / TEE sign σ for this
  //     authorization (injected port; vendor-gated in prod). Each σ carries the
  //     gate's per-stanza share material.
  const sigmas = await deps.sigmaGatherer.gatherSigmas(ref.sigma_request);

  // (2) Vault read — ciphertext + inseparable commit binding (C1). The vault
  //     never holds the DEK or plaintext.
  const blob = await deps.vault.getBlob(ref.vault_ref);

  // (3) Combine + decrypt. The combiner reconstructs the DEK from the σ-carried
  //     shares and AEAD-decrypts the vault ciphertext → plaintext.
  const runner = deps.combineAndDecryptRunner ?? runM3CombinerBridge;
  const result: RunM3CombinerBridgeResult = runner({
    combinerInput: {
      authorizationId: input.event.authorizationId,
      hCommit: input.event.h_commit,
      authorizationBlock: input.event.authorization_block,
      blockHash: input.event.block_hash ?? input.chain_proofs.reveal_authorized_block_hash,
      commitAAD: blob.commitBinding.commit_aad_bytes,
      ageEnvelope: blob.ciphertext,
      sigmas,
      registrySnapshots: ref.registry_snapshots,
      canonicalAddressPin: ref.canonical_address_pin,
      ...(ref.conditional_recipients_policy === undefined
        ? {}
        : { conditionalRecipientsPolicy: ref.conditional_recipients_policy }),
    },
  });

  if (!result.ok) {
    // Fail-CLOSED: the combiner did not produce plaintext (gate σ insufficient,
    // share material bad, vendor pin / commit-AAD mismatch, etc.). Surface the
    // combiner's own code in safe_refs; never fall back to a request plaintext.
    throw new HttpProblem(
      problemFromCode("COMBINER_GATE_AUTHORIZATION_MISSING", input.event.authorizationId, {
        detail: `combiner refused to produce plaintext: ${result.code}`,
        safe_refs: {
          combiner_code: result.code,
          sub_codes: result.subCodes.join(","),
        },
        retryable: false,
      }),
    );
  }
  return { plaintext: result.plaintext };
}

/** Best-effort zeroize of transient plaintext bytes (crypto hygiene). */
function zeroizeBytes(buffer: Uint8Array | undefined): void {
  if (buffer instanceof Uint8Array) buffer.fill(0);
}

/** Drop every own-enumerable key from the decoded full-plaintext record so no
 *  cleartext lingers in this scope after bundle assembly. The recipient-
 *  filtered copies in the persisted bundles are unaffected. */
function clearRecord(record: Readonly<Record<string, unknown>> | undefined): void {
  if (record === undefined) return;
  for (const key of Object.keys(record)) {
    delete (record as Record<string, unknown>)[key];
  }
}

function assertRevealPreconditions(preconditions: RevealPreconditions): void {
  if (!preconditions.challenge_window_closed) throw new Error("Reveal precondition failed: challenge window open.");
  if (!preconditions.shred_state_allows_reveal) throw new Error("Reveal precondition failed: shred state blocks reveal.");
  if (!preconditions.registry_deprecation_acceptable) {
    throw new Error("Reveal precondition failed: registry deprecation state unacceptable.");
  }
  if (!preconditions.recipient_policy_identified) {
    throw new Error("Reveal precondition failed: recipient policy missing.");
  }
}

function timestampToIso(seconds: bigint): string {
  return new Date(Number(seconds) * 1000).toISOString();
}

function challengeWindowExpiredAt(event: RevealAuthorizedEvent): string {
  return new Date(Number(event.authorization_timestamp + BigInt(event.challenge_window)) * 1000).toISOString();
}

export * from "./event-listener.js";
export * from "./sigma-gathering.js";
export * from "./m3-bridge.js";
export * from "./art-18-defer.js";
export * from "./refusal-handler.js";
