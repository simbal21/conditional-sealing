// Reveal-time per-gate stanza unwrap (S2-1 §6.2.3 inverse) — the seam that turns
// each gate's σ request into a recovered Shamir share WITHOUT the server ever
// loading a raw share.
//
// THE NON-CUSTODY SEAM
// --------------------
// At ingest, each dealt DEK share was hybrid-PQ-wrapped to ITS gate's recipient
// pubkey and stored ONLY in that wrapped form (`dek_share_records.wrapped_payload`
// + the age envelope). At reveal, each gate (the local stub holding its gate
// PRIVATE key; the real Lit/G3/G4 TEE/threshold network in production) unwraps
// ONLY its own stanza → recovers its share → returns it in σ evidence metadata
// (`shareHex`). The σ-gatherer assembles the 4 gates' σ; the combiner gathers the
// shares → `combineDek` → DEK. NO server-side share-load, NO single party holds
// enough to reconstruct.
//
// This `UnwrappingGateSigningClient` wraps a BASE gate-signing client (which
// produces the gate's σ over `(authorizationId, h_commit, block_hash)` — the
// authorization signature) and ADDS the per-stanza unwrap. The base client is
// the vendor boundary; in production it is the real network/TEE adapter and the
// unwrap happens INSIDE the gate's enclave (the private key never leaves it).
// Locally the stub client + the injected `GatePrivateKeyProvider` stand in for
// that enclave so the real-stack E2E runs end-to-end.
//
// V3 isolation: crypto from @cealis/v3-crypto via the m1 facade.

import {
  decodeWrappedStanzaPayload,
  unwrapShareForRecipient,
  type HybridWrapRecipientPrivateKeys,
  type Hex32,
} from "../m1-imports.js";
import type { GateSigningClient } from "./sigma-gathering.js";
import type {
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "../m3-imports.js";

/** A wrapped stanza for one gate + the routing metadata needed to unwrap it. */
export interface GateWrappedStanza {
  readonly stanza_index: number;
  readonly binding_tag: Hex32;
  readonly share_domain: number;
  readonly share_role: number;
  readonly logical_index: number;
  readonly x: number;
  /** §6.2 wrapped stanza payload (pk_eph ‖ ct_mlkem ‖ wrapped_share). */
  readonly wrapped_payload: Uint8Array;
  /** The plugin_version_digest the §6.2 wrap AAD bound (32 bytes). */
  readonly plugin_version_digest: Uint8Array;
  /** The commit_context_digest_N the §6.2 wrap AAD bound (32 bytes). */
  readonly commit_context_digest_N: Uint8Array;
  /** The commit_context_digest_0 the AEAD payload was sealed under (32 bytes). */
  readonly commit_context_digest_0: Uint8Array;
}

/**
 * Per-gate stanza + private-key source for one reveal. Resolves, for a given
 * `(gateKind, conditionalRecipientIndex)`, the wrapped stanza this gate must
 * unwrap and the gate's PRIVATE KEM keys.
 *
 * PRODUCTION: the wrapped stanza comes from the age envelope (vault) /
 * `dek_share_records`, and the private keys live INSIDE the gate's TEE / threshold
 * network — this port is the gate's own enclave-internal lookup, never a server
 * read of a gate private key.
 *
 * LOCAL E2E: the composition root reads `dek_share_records` for the in-flight
 * `h_commit` and holds the per-commit gate private keys it generated at ingest.
 */
export interface GateStanzaUnwrapSource {
  resolve(input: {
    readonly authorizationId: Hex32;
    readonly hCommit: Hex32;
    readonly gateKind: number;
    readonly conditionalRecipientIndex: number;
  }):
    | Promise<{ readonly stanza: GateWrappedStanza; readonly recipient: HybridWrapRecipientPrivateKeys }>
    | { readonly stanza: GateWrappedStanza; readonly recipient: HybridWrapRecipientPrivateKeys };
}

/** Hex helper (lowercase, 0x-prefixed). */
function bytesToHex(bytes: Uint8Array): Hex32 {
  return ("0x" + Buffer.from(bytes).toString("hex")) as Hex32;
}

/**
 * A gate-signing client that ALSO unwraps its own stanza and threads the
 * recovered Shamir share into σ metadata (`shareHex`). Decorates a base client
 * that produces the gate's authorization σ; the base client's σ is preserved.
 */
export class UnwrappingGateSigningClient implements GateSigningClient {
  readonly gateKind: GateSigningClient["gateKind"];
  private readonly base: GateSigningClient;
  private readonly source: GateStanzaUnwrapSource;

  constructor(input: { readonly base: GateSigningClient; readonly source: GateStanzaUnwrapSource }) {
    this.gateKind = input.base.gateKind;
    this.base = input.base;
    this.source = input.source;
  }

  async requestSigma(
    input: RequestSigmaInput<unknown>,
  ): Promise<RequestSigmaResult & { sigma: Uint8Array }> {
    // 1. The base gate produces its authorization σ (the vendor boundary).
    const signed = await this.base.requestSigma(input);

    // 2. The gate unwraps ITS stanza with ITS private key → recovers ITS share.
    //    conditionalRecipientIndex is carried on the base request via extras OR
    //    defaults to 0 for the top-level gates.
    const conditionalRecipientIndex = readConditionalIndex(input);
    const { stanza, recipient } = await this.source.resolve({
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      gateKind: this.gateKind,
      conditionalRecipientIndex,
    });

    const wrapped = decodeWrappedStanzaPayload(stanza.wrapped_payload);
    const unwrapped = unwrapShareForRecipient({
      stanza_index: stanza.stanza_index,
      binding_tag: stanza.binding_tag,
      plugin_version_digest: stanza.plugin_version_digest,
      commit_context_digest_N: stanza.commit_context_digest_N,
      share_domain: stanza.share_domain as never,
      share_role: stanza.share_role as never,
      logical_index: stanza.logical_index,
      x: stanza.x,
      recipient,
      wrapped,
    });
    if (!unwrapped.ok) {
      throw new Error(
        `gate ${this.gateKind} stanza unwrap failed (${unwrapped.error}) — the gate's private ` +
          "key could not open its wrapped share (a single gate cannot recover the DEK).",
      );
    }

    // 3. Thread the recovered share + the AEAD context into σ metadata. The
    //    gatherer overrides only verified/verifyCode/stanzaIndex; shareHex +
    //    commitContextDigest0 flow through to the combiner's orchestrator.
    const metadata: Record<string, string | number | bigint | Hex32> = {
      ...signed.metadata,
      shareHex: bytesToHex(unwrapped.share),
      commitContextDigest0: bytesToHex(stanza.commit_context_digest_0),
    };
    // Best-effort zeroize the recovered share copy we just hex-encoded; the hex
    // string is the only carrier from here on (it is consumed + zeroized by the
    // combiner). The underlying Uint8Array can be wiped.
    unwrapped.share.fill(0);

    return { ...signed, metadata };
  }

  verifySigma(input: RequestSigmaInput<unknown> & { sigma: Uint8Array }): Promise<VerifySigmaResult> {
    return Promise.resolve(this.base.verifySigma(input));
  }
}

/** Read the conditional-recipient index from the request extras (default 0). */
function readConditionalIndex(input: RequestSigmaInput<unknown>): number {
  const extras = input.extras;
  if (extras !== null && typeof extras === "object" && "conditionalRecipientIndex" in extras) {
    const value = (extras as { conditionalRecipientIndex?: unknown }).conditionalRecipientIndex;
    if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  }
  return 0;
}
