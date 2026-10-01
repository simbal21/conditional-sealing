import { randomBytes } from "node:crypto";
import type { EncryptPayloadOutput } from "../m1-imports.js";
import { encryptPayload } from "../m1-imports.js";
import type { HCommitArtifacts } from "../h-commit/index.js";

export interface SealedCodeSealInput {
  readonly plaintext: Uint8Array;
  readonly hCommit: HCommitArtifacts;
}

export interface SealedCodeSealOutput extends EncryptPayloadOutput {
  readonly envelope_ref: string;
}

/**
 * ⚠️ TEE STUB — NOT PRODUCTION-SAFE (Decision D9; audit 2026-05-19 api/sd/verify CRITICAL).
 *
 * Generates the DEK in ordinary Node.js process memory with NO attestation and returns a
 * `sealed-code://` envelope_ref that LOOKS sealed but carries no TEE guarantee — a
 * fake-success stub (Rule 19 class). The real implementation MUST be a Nitro Enclave /
 * cloud HSM-TEE call (the swappable Phase-1↔Phase-2 boundary). The hard
 * `NODE_ENV === "production"` guard below makes the stub fail loudly instead of silently
 * shipping fake-sealed output. Remove the guard only when the real TEE boundary replaces
 * this body. See `docs/audits/live-system-audit-synthesis.md`.
 */
export function sealPlaintextForVault(input: SealedCodeSealInput): SealedCodeSealOutput {
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "TEE STUB sealPlaintextForVault must not run in production — replace with the real " +
        "Nitro Enclave / cloud HSM-TEE call before any production/pilot use (Decision D9).",
    );
  }
  const dek = randomBytes(32);
  const encrypted = encryptPayload({
    dek,
    commit_context_digest_0: input.hCommit.commit_context_digest.startsWith("0x")
      ? Buffer.from(input.hCommit.commit_context_digest.slice(2), "hex")
      : Buffer.alloc(32),
    commit_AAD_v0: input.hCommit.commit_AAD,
    plaintext: input.plaintext,
  });
  dek.fill(0);
  return {
    ...encrypted,
    envelope_ref: `sealed-code://${input.hCommit.h_commit}`,
  };
}

