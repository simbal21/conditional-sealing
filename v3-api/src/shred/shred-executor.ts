// ShredExecutor — the real crypto-shred cascade (GDPR Art. 17 right-to-erasure).
// T4.2 (Phase 3 Wave 4).
//
// This is the API-side execution path the subject + partner shred-request routes
// call after the route has authenticated the principal and looked up the escrow.
// The route owns "may THIS principal even ask?"; the executor owns the full
// crypto-shred cascade and its fail-closed ordering.
//
// THE CASCADE (legal-constraints.md "Crypto-Shredding" + internal project constitution §0 P11 +
// internal shred-condition design §11.3 triple block):
//
//   (0) RESOLVE the PDA `shredding_authority` (subject/joint/operator/timelock/
//       disabled). `disabled` is a FEATURE (testament / archival / evidence
//       provenance) — erasure is deliberately off → REJECT loud, nothing touched.
//   (1) GUARDRAIL — read the LIVE on-chain shred state (T3.4 ShredStateLivePort,
//       no cache). The mandatory `NOT post_challenge_reveal_in_progress` guardrail
//       (PDA+ guardrail, NOT partner-configurable) fires here so a shred can NEVER
//       race a post-challenge reveal that is signing gates. A shred already
//       `finalized` on-chain is idempotent-complete, not a re-run.
//   (2) DESTROY the DEK shares — delete the `dek_share_records` rows for this
//       h_commit. IRREVERSIBLE. Once the threshold of gate shares is gone the DEK
//       can never be reconstructed, so the AEAD ciphertext is permanently opaque
//       even if it somehow survived. Shares are key material; this is the
//       cryptographic core of crypto-shred.
//   (3) VAULT delete — `vault.deleteBlob` removes the ciphertext + inseparable
//       commit binding and writes the vault layer's append-only shred-audit row
//       (vault_audit_log, 0003 trigger). `shredAuthority === "disabled"` is also
//       rejected at the vault boundary; we reject earlier so we never reach it.
//   (4) ON-CHAIN ShredRegistry write — the §11.3 triple block's chain leg: G1
//       refuses any FUTURE reveal authorization and G4 refuses σ_G4 once the
//       registry records the shred. This tx uses the INJECTED
//       `ShredExecutorChainPort` (wallet client is vendor/key-gated — env/KMS,
//       never a checked-in `keys/` file; build-to-edge, wired at Wave 5).
//   (5) AUDIT — append a shred row keyed by h_commit to the append-only audit
//       log (actor + authority + reason). Append-only: NEVER UPDATE/DELETE.
//
// FAIL-CLOSED ORDERING: the guardrail is checked BEFORE any destructive step so a
// blocked shred touches nothing. Once shares are destroyed the operation is past
// the point of no return; a later step throwing surfaces loudly with the
// pre-declared error context so the cascade can be reconciled, never silently
// "succeeds" (Rule 19 fake-success class).
//
// PLATFORM PRINCIPLE: nothing about the flow is hardcoded. The authority comes
// from the PDA `shredding_authority`; the vault ref, reason, and chain pda-root
// all arrive from the caller (resolved from the PDA / escrow record). The
// executor is one path that every use case's shred reads through.
//
// ISOLATION (SECURITY.md): no @cealis/shared, no V1 package imports,
// no V1 env vars (the sealed-share / issuer-salt / committee-key family), no V1
// TAG_*_V1 constants, no checked-in `keys/` read — the chain wallet client lives
// behind the injected `ShredExecutorChainPort`, never constructed from a file
// here.

import type { Hex32 } from "../types/reveal-artifact-bundle.js";
import type { ShredAuthority } from "../vault/cealis-v3-vault.js";
import type { CealisV3Vault } from "../vault/cealis-v3-vault.js";
import type { ShredStateLivePort } from "../reveal/reveal-coordinator-impl.js";

/**
 * Destroyer of the `dek_share_records` rows for an h_commit (the irreversible
 * DEK-share destruction step). SEPARATE seam from the ingest-side
 * `ShareRecordStore.persist` (vault-writer-impl.ts) — persistence and
 * destruction are different concerns with different blast radii. The production
 * impl runs `DELETE FROM dek_share_records WHERE h_commit = $1` over the injected
 * V3 Drizzle client; tests inject a fake. There is NO read-back / restore path.
 */
export interface ShareRecordDestroyer {
  /**
   * Destroy every DEK share row for `hCommit`. Returns the number of rows
   * destroyed (0 = already shredded / never existed — the caller treats a
   * second-time 0 as idempotent, not an error). IRREVERSIBLE.
   */
  destroyShares(hCommit: Hex32): Promise<number>;
}

/**
 * The injected on-chain ShredRegistry write port (the §11.3 chain leg —
 * G1 refuse-future + G4 refuse). Build-to-edge: this is where the
 * vendor/key-gated `WalletClient` lives. Phase 3 wires a real
 * `ViemShredExecutorChainPort` over the ShredRegistry ABI at the composition
 * root (Wave 5); the wallet client comes from env/KMS, NEVER a file (R2x grep
 * gate). Tests inject a deterministic fake that records the call.
 *
 * The port exposes the two ShredRegistry on-chain transitions the cascade needs:
 * `requestShred` (records the request + flips G1/G4 to refuse) and
 * `finalizeShred` (records finalization, publishing the public `proof_shred`
 * verification token — NOT key material per §11.5).
 */
export interface ShredExecutorChainPort {
  /**
   * Write the ShredRegistry state that makes G1 refuse future reveal
   * authorizations and G4 refuse σ_G4 for this h_commit. Maps to the on-chain
   * `requestShred(hCommit, pdaRoot, reason)` (then `finalizeShred`) surface.
   * The impl owns the request→finalize sequencing and per-PDA latency; the
   * cascade only needs "the chain now refuses." Returns the tx hash + the
   * published `proof_shred` token (public, safe to surface).
   */
  recordShred(input: {
    readonly hCommit: Hex32;
    /** PDA root the shred is bound to (`requestShred` arg 2). PDA-derived. */
    readonly pdaRoot: Hex32;
    /** Reason digest for the shred (`requestShred` arg 3). PII-allow-list-safe. */
    readonly reasonDigest: Hex32;
  }): Promise<{ readonly txHash: string; readonly proofShred: Hex32 }>;
}

/**
 * Append-only shred-audit writer keyed by h_commit (cascade step 5). Writes one
 * immutable row to `vault_audit_log` (action `shred.finalized`) carrying the
 * authority + actor + reason. Append-only by DB trigger (0003) — the writer
 * MUST only INSERT; never UPDATE/DELETE (legal chain-of-custody requirement).
 * Distinct from the vault layer's own per-ref shred-audit row (step 3): this row
 * is keyed by h_commit and records the WHO/WHY of the erasure for the subject's
 * audit export.
 */
export interface ShredAuditWriter {
  appendShredAudit(input: {
    readonly hCommit: Hex32;
    readonly shredAuthority: ShredAuthority;
    /** The principal that triggered the shred (subject user id / partner id /
     *  operator ref). Goes to `actor_ref`. */
    readonly actorRef: string;
    /** Optional opaque reason reference from the request body. */
    readonly requestReasonRef?: string;
    readonly partnerId?: string;
    readonly pdaId?: string;
  }): Promise<void>;
}

/**
 * The narrow inputs the cascade needs that the route resolves from the escrow /
 * PDA record. Nothing here is hardcoded — every field is PDA/escrow-derived.
 */
export interface ShredExecutionRequest {
  readonly hCommit: Hex32;
  /** PDA-configured shred authority (lowercase vault enum form). The route maps
   *  the capitalized escrow `shred_authority` to this before calling. */
  readonly shredAuthority: ShredAuthority;
  /** Opaque vault ref the ciphertext is stored under (resolved from the escrow /
   *  PDA, since the vault is keyed by opaque ref, not h_commit). */
  readonly vaultRef: string;
  /** PDA root the on-chain shred binds to. */
  readonly pdaRoot: Hex32;
  /** Reason digest for the on-chain `requestShred`. */
  readonly reasonDigest: Hex32;
  /** The principal that triggered the shred (for the audit row). */
  readonly actorRef: string;
  /** Optional opaque reason reference from the request body. */
  readonly requestReasonRef?: string;
  readonly partnerId?: string;
  readonly pdaId?: string;
}

/** Reason codes for a `ShredExecutionError`. Pre-declared per Rule 47 so the
 *  caller can branch without a debugger. */
export type ShredExecutionReason =
  | "SHRED_AUTHORITY_DISABLED"
  | "SHRED_BLOCKED_POST_CHALLENGE_REVEAL"
  | "SHRED_BLOCKED_ALREADY_FINALIZED"
  | "SHRED_SHARE_DESTROY_FAILED"
  | "SHRED_VAULT_DELETE_FAILED"
  | "SHRED_CHAIN_WRITE_FAILED"
  | "SHRED_AUDIT_WRITE_FAILED";

/** Which cascade step was executing when the error was raised (diagnostics). */
export type ShredExecutionStep =
  | "authority-check"
  | "guardrail"
  | "destroy-shares"
  | "vault-delete"
  | "chain-write"
  | "audit-append";

export interface ShredExecutionErrorContext {
  readonly hCommit: Hex32;
  readonly shredAuthority: ShredAuthority;
  readonly step: ShredExecutionStep;
  readonly reasonCode: ShredExecutionReason;
  /** Live shred state observed at the guardrail read (when relevant). */
  readonly liveShredState?: "none" | "requested" | "finalized";
  readonly postChallengeRevealInProgress?: boolean;
  /** How many share rows were destroyed before the failure (cascade reconcile). */
  readonly sharesDestroyed?: number;
  readonly vaultRef?: string;
  readonly partnerId?: string;
  readonly pdaId?: string;
  /** The underlying error when a cascade step's dependency threw (DB / chain). */
  readonly cause?: unknown;
}

/** Loud, fail-closed cascade error. Never thrown to mean "succeeded." */
export class ShredExecutionError extends Error {
  readonly context: ShredExecutionErrorContext;
  constructor(message: string, context: ShredExecutionErrorContext) {
    super(message);
    this.name = "ShredExecutionError";
    this.context = context;
  }
}

/** Result of a completed cascade (every destructive step landed). */
export interface ShredExecutionResult {
  readonly hCommit: Hex32;
  readonly shredAuthority: ShredAuthority;
  readonly shreddedAt: string;
  readonly sharesDestroyed: number;
  readonly vaultRef: string;
  /** On-chain tx hash for the ShredRegistry write. */
  readonly chainTxHash: string;
  /** Public `proof_shred` verification token (NOT key material). */
  readonly proofShred: Hex32;
}

export interface ShredExecutorOptions {
  /** Reads the LIVE on-chain shred state for the guardrail (T3.4, no cache). */
  readonly shredStatePort: ShredStateLivePort;
  /** Destroys the `dek_share_records` rows (irreversible). */
  readonly shareDestroyer: ShareRecordDestroyer;
  /** The real opaque-ciphertext vault (T0.3). Used for `deleteBlob`. */
  readonly vault: CealisV3Vault;
  /** Injected on-chain ShredRegistry write port (§11.3 chain leg). */
  readonly chainPort: ShredExecutorChainPort;
  /** Append-only audit writer (vault_audit_log, keyed by h_commit). */
  readonly auditWriter: ShredAuditWriter;
  /** Wall-clock source (injectable for deterministic tests). */
  readonly now?: () => Date;
}

/**
 * The real crypto-shred executor. The composition root (Wave 5) constructs one
 * with the live shred-state port, a DB-backed share destroyer + audit writer,
 * the real vault, and the viem-backed chain port, then threads it into the
 * subject + partner route contexts so the shred-request routes call `execute`.
 */
export class ShredExecutor {
  private readonly shredStatePort: ShredStateLivePort;
  private readonly shareDestroyer: ShareRecordDestroyer;
  private readonly vault: CealisV3Vault;
  private readonly chainPort: ShredExecutorChainPort;
  private readonly auditWriter: ShredAuditWriter;
  private readonly now: () => Date;

  constructor(options: ShredExecutorOptions) {
    this.shredStatePort = options.shredStatePort;
    this.shareDestroyer = options.shareDestroyer;
    this.vault = options.vault;
    this.chainPort = options.chainPort;
    this.auditWriter = options.auditWriter;
    this.now = options.now ?? (() => new Date());
  }

  /**
   * Run the full crypto-shred cascade. Throws `ShredExecutionError` (fail-closed)
   * on a disabled authority, an active guardrail, or any cascade-step failure.
   */
  async execute(request: ShredExecutionRequest): Promise<ShredExecutionResult> {
    const { hCommit, shredAuthority, vaultRef } = request;

    // (0) AUTHORITY — `disabled` PDAs deliberately have NO erasure path. Reject
    //     before touching anything. (The route already gate-checks subject vs
    //     partner authority; this is the defense-in-depth backstop so a
    //     `disabled` PDA can never be shredded even if a route mis-wires.)
    if (shredAuthority === "disabled") {
      throw new ShredExecutionError("shred authority disabled — erasure not permitted for this PDA", {
        hCommit,
        shredAuthority,
        step: "authority-check",
        reasonCode: "SHRED_AUTHORITY_DISABLED",
        vaultRef,
        ...refs(request),
      });
    }

    // (1) GUARDRAIL — read the LIVE on-chain shred state (no cache, fail-closed).
    //     The mandatory `NOT post_challenge_reveal_in_progress` guardrail forbids
    //     racing a post-challenge reveal that is gathering gate signatures.
    let live: Awaited<ReturnType<ShredStateLivePort["read"]>>;
    try {
      live = await this.shredStatePort.read(hCommit);
    } catch (cause) {
      // An unreadable chain state must BLOCK the shred (fail-closed), never
      // proceed on a permissive default.
      throw new ShredExecutionError("live shred-state read failed — refusing to shred (fail-closed)", {
        hCommit,
        shredAuthority,
        step: "guardrail",
        reasonCode: "SHRED_BLOCKED_POST_CHALLENGE_REVEAL",
        vaultRef,
        ...refs(request),
        cause,
      });
    }

    if (live.post_challenge_reveal_in_progress) {
      // A post-challenge reveal is in progress (ShredState.ChallengeOpen). The
      // mandatory guardrail forecloses the shred-vs-gate-signing race.
      throw new ShredExecutionError(
        "shred blocked: post-challenge reveal in progress (mandatory NOT-post-challenge-reveal-in-progress guardrail)",
        {
          hCommit,
          shredAuthority,
          step: "guardrail",
          reasonCode: "SHRED_BLOCKED_POST_CHALLENGE_REVEAL",
          liveShredState: live.state,
          postChallengeRevealInProgress: true,
          vaultRef,
          ...refs(request),
        },
      );
    }
    if (live.state === "finalized") {
      // The shred has already progressed past a recoverable point on-chain.
      // Re-running the destructive cascade would be a no-op at best; surface it
      // as an already-finalized block so the caller does not double-execute.
      throw new ShredExecutionError("shred blocked: already finalized on-chain", {
        hCommit,
        shredAuthority,
        step: "guardrail",
        reasonCode: "SHRED_BLOCKED_ALREADY_FINALIZED",
        liveShredState: live.state,
        postChallengeRevealInProgress: false,
        vaultRef,
        ...refs(request),
      });
    }

    const shreddedAt = this.now().toISOString();

    // (2) DESTROY the DEK shares — irreversible. Past this point the DEK can
    //     never be reconstructed; the cascade is committed.
    let sharesDestroyed: number;
    try {
      sharesDestroyed = await this.shareDestroyer.destroyShares(hCommit);
    } catch (cause) {
      throw new ShredExecutionError("DEK share destruction failed", {
        hCommit,
        shredAuthority,
        step: "destroy-shares",
        reasonCode: "SHRED_SHARE_DESTROY_FAILED",
        vaultRef,
        ...refs(request),
        cause,
      });
    }

    // (3) VAULT delete — ciphertext + inseparable binding removed; the vault
    //     layer appends its own per-ref shred-audit row (append-only).
    try {
      await this.vault.deleteBlob({ ref: vaultRef, shredAuthority });
    } catch (cause) {
      // Shares are already destroyed (the data is unrecoverable regardless), so
      // surface loudly with the shares-destroyed count for reconcile, but do NOT
      // pretend the cascade succeeded.
      throw new ShredExecutionError("vault blob deletion failed (shares already destroyed)", {
        hCommit,
        shredAuthority,
        step: "vault-delete",
        reasonCode: "SHRED_VAULT_DELETE_FAILED",
        sharesDestroyed,
        vaultRef,
        ...refs(request),
        cause,
      });
    }

    // (4) ON-CHAIN ShredRegistry write — G1 refuses future reveal authorization,
    //     G4 refuses σ_G4. Injected wallet-client port (vendor/key-gated).
    let chain: { readonly txHash: string; readonly proofShred: Hex32 };
    try {
      chain = await this.chainPort.recordShred({
        hCommit,
        pdaRoot: request.pdaRoot,
        reasonDigest: request.reasonDigest,
      });
    } catch (cause) {
      throw new ShredExecutionError("on-chain ShredRegistry write failed (shares + vault already gone)", {
        hCommit,
        shredAuthority,
        step: "chain-write",
        reasonCode: "SHRED_CHAIN_WRITE_FAILED",
        sharesDestroyed,
        vaultRef,
        ...refs(request),
        cause,
      });
    }

    // (5) AUDIT — append-only shred row keyed by h_commit (WHO/WHY).
    try {
      await this.auditWriter.appendShredAudit({
        hCommit,
        shredAuthority,
        actorRef: request.actorRef,
        ...(request.requestReasonRef !== undefined ? { requestReasonRef: request.requestReasonRef } : {}),
        ...(request.partnerId !== undefined ? { partnerId: request.partnerId } : {}),
        ...(request.pdaId !== undefined ? { pdaId: request.pdaId } : {}),
      });
    } catch (cause) {
      throw new ShredExecutionError("shred audit append failed (erasure completed; audit row missing)", {
        hCommit,
        shredAuthority,
        step: "audit-append",
        reasonCode: "SHRED_AUDIT_WRITE_FAILED",
        sharesDestroyed,
        vaultRef,
        ...refs(request),
        cause,
      });
    }

    return {
      hCommit,
      shredAuthority,
      shreddedAt,
      sharesDestroyed,
      vaultRef,
      chainTxHash: chain.txHash,
      proofShred: chain.proofShred,
    };
  }
}

/** Pull the optional partner/pda refs into the error-context bag. */
function refs(request: ShredExecutionRequest): {
  partnerId?: string;
  pdaId?: string;
} {
  return {
    ...(request.partnerId !== undefined ? { partnerId: request.partnerId } : {}),
    ...(request.pdaId !== undefined ? { pdaId: request.pdaId } : {}),
  };
}

/**
 * Map the capitalized escrow/PDA `shred_authority` enum
 * (`"Subject" | "Joint" | "Operator" | "Timelock" | "Disabled"`) to the
 * lowercase vault `ShredAuthority` the executor + vault use. Exported so the
 * routes share one normalization (no per-route drift).
 */
export function normalizeShredAuthority(
  authority: "Subject" | "Joint" | "Operator" | "Timelock" | "Disabled",
): ShredAuthority {
  switch (authority) {
    case "Subject":
      return "subject";
    case "Joint":
      return "joint";
    case "Operator":
      return "operator";
    case "Timelock":
      return "timelock";
    case "Disabled":
      return "disabled";
  }
}
