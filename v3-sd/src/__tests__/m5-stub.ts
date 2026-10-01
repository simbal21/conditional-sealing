// M5 ingestion stub for in-package SD pipeline tests.
//
// PHASE A: signature scaffold only — Phase B fills body, Phase E re-uses.
//
// Rationale: M5 has not shipped at M6 launch (PHASE-PLAN §1 Rule 44 deferral).
// M6 must self-contain its asymmetric-isolation + Mode-B + crypto-shred
// integration tests via this in-process stub mimicking M5's
// `POST /v1/ingestion/mode-a` call shape. NO HTTP, NO DB, NO chain.
//
// At M8, the live M5 wire replaces this stub.

import type { Bytes32 } from "../tags/preimages.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { concatBytes } from "../encoding/field-encoding.js";

export interface M5IngestionRequest {
  readonly authorizationId: Bytes32;
  readonly pda_id: Bytes32;
  readonly pda_version: bigint;
  readonly schema_digest: Bytes32;
  readonly partner_id: Bytes32;
  /** Mode A only; Mode B passes here trigger ERR_SD_CONFIG_MODE_B_INCOMPATIBLE downstream of SD. */
  readonly ingestion_mode: "MODE_A" | "MODE_B";
  /**
   * Plaintext payload — exists only inside this stub's process memory; Phase B
   * implementation must zeroize after SD execution completes (per §2.6).
   */
  readonly plaintext: Record<string, unknown>;
  /** Escrow DEK for HKDF salt derivation per §2.4. 32 bytes. */
  readonly dek: Uint8Array;
}

export interface M5IngestionResultEscrowOk {
  readonly kind: "ok";
  readonly h_commit: Bytes32;
  readonly pda_root: Bytes32;
  readonly commit_AAD_sdMerkleRoot: Bytes32; // 32 zero bytes if SD disabled / failed before root
  readonly escrow_envelope_bytes_count: number;
}

export interface M5IngestionResultEscrowErr {
  readonly kind: "err";
  readonly code: "VAULT_WRITE_FAILED" | "G4_REFUSED" | "PDA_LOOKUP_FAILED";
}

export type M5IngestionResult = M5IngestionResultEscrowOk | M5IngestionResultEscrowErr;

/**
 * `M5IngestionStub` — interface Phase B implements + Phase E imports as
 * source-file pointer (per M5 lesson 2). Phase B fills body.
 *
 * Stub contract: deterministically returns escrow-ok / escrow-err based on
 * injected fixtures. Used to drive §15.2 7-row asymmetric-isolation matrix
 * + Mode B two-branch test + crypto-shred orphan test (Phase E).
 */
export interface M5IngestionStub {
  /** Execute a synthetic ingestion. Phase B body returns deterministic mocks. */
  execute(req: M5IngestionRequest): Promise<M5IngestionResult>;

  /**
   * Inject a failure mode for the next call. Used by isolation tests to
   * drive each §15.2 stage's escrow/SD interaction.
   */
  injectFailureForNextCall(failure: M5IngestionResultEscrowErr | null): void;
}

export class DeterministicM5IngestionStub implements M5IngestionStub {
  #nextFailure: M5IngestionResultEscrowErr | null = null;

  async execute(req: M5IngestionRequest): Promise<M5IngestionResult> {
    if (this.#nextFailure) {
      const failure = this.#nextFailure;
      this.#nextFailure = null;
      return failure;
    }
    const payloadDigest = keccak_256(utf8ToBytes(JSON.stringify(stable(req.plaintext))));
    const pda_root = keccak_256(concatBytes([req.pda_id, req.schema_digest, req.partner_id]));
    const h_commit = keccak_256(concatBytes([req.authorizationId, pda_root, payloadDigest]));
    return {
      kind: "ok",
      h_commit,
      pda_root,
      commit_AAD_sdMerkleRoot: new Uint8Array(32) as Bytes32,
      escrow_envelope_bytes_count: payloadDigest.length + req.dek.length,
    };
  }

  injectFailureForNextCall(failure: M5IngestionResultEscrowErr | null): void {
    this.#nextFailure = failure;
  }
}

export function createM5IngestionStub(): M5IngestionStub {
  return new DeterministicM5IngestionStub();
}

function stable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, stable(v)]));
  }
  return value;
}
