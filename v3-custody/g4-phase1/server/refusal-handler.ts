import { encryptReasonBlob } from "./encrypted-reason.js";
import { signRefusalClaim, type SignedRefusalClaim } from "./refusal-claim.js";

export const RefusalCode = {
  LegalCompel: 0x01,
  Art17Erasure: 0x02,
  Art18Restriction: 0x03,
  IntegrityFail: 0x04,
  ChainMismatch: 0x05,
  PluginDeprecated: 0x06,
  AuthorityDeprecated: 0x07,
  DslDeprecated: 0x08,
  OracleDeprecated: 0x09,
  OptOutActive: 0x0a,
} as const;

export interface RefusalRegistryWriter {
  refusePublic(authorizationId: string, hCommit: string, reasonCode: number, proofRef: string): Promise<string>;
  refuseEncrypted(authorizationId: string, hCommit: string, reasonCode: number, encryptedReasonBlob: Uint8Array): Promise<string>;
  recordAdvisorySignal(authorizationId: string, hCommit: string, reasonCode: number): Promise<string>;
}

export interface HandleRefusalInput {
  readonly authorizationId: string;
  readonly hCommit: string;
  readonly reasonCode: number;
  readonly proofRef: string;
  readonly reasonPlaintext?: Uint8Array;
  readonly encryptedReasonKey: Uint8Array;
  readonly registry: RefusalRegistryWriter;
  /** Unix-seconds timestamp the claim is bound to. Caller supplies this so the
   *  refusal claim binds to the request time (not server-process time, which can
   *  drift across multiple Railway replicas). */
  readonly timestamp: bigint;
  /** Daemon's Ed25519 signing key (PEM). REQUIRED for relay-claim-only mode:
   *  the daemon produces an off-chain audit-grade signed claim that the orchestrator
   *  can submit to G4RefusalRegistry alongside its OPERATOR_ROLE chain write. */
  readonly signingKeyPem: string;
}

export interface HandleRefusalResult {
  readonly signed: boolean;
  readonly txHash: string;
  readonly encryptedBlobHash?: string;
  /** Daemon's Ed25519-signed audit-grade claim. Always present in relay-claim-only
   *  mode regardless of txHash. Off-chain verifiable against the daemon's authority
   *  pubkey. The orchestrator persists this alongside the on-chain refusal write
   *  so audit can later verify "the daemon DID agree to this refusal" — closes the
   *  fraud-by-refusal attack where a compromised orchestrator writes refusals the
   *  daemon never authorized. */
  readonly refusalClaim: SignedRefusalClaim;
}

export async function handleRefusal(input: HandleRefusalInput): Promise<HandleRefusalResult> {
  if (isBlocking(input.reasonCode)) {
    if (input.reasonCode === RefusalCode.Art17Erasure || input.reasonCode === RefusalCode.Art18Restriction) {
      const plaintext = input.reasonPlaintext ?? new Uint8Array(0);
      const encrypted = encryptReasonBlob(plaintext, input.encryptedReasonKey);
      const refusalClaim = signRefusalClaim(
        {
          authorizationId: input.authorizationId,
          hCommit: input.hCommit,
          reasonCode: input.reasonCode,
          encryptedBlobHash: encrypted.encryptedBlobHash,
          timestamp: input.timestamp,
        },
        input.signingKeyPem,
      );
      const txHash = await input.registry.refuseEncrypted(
        input.authorizationId,
        input.hCommit,
        input.reasonCode,
        encrypted.encryptedReasonBlob,
      );
      return { signed: false, txHash, encryptedBlobHash: encrypted.encryptedBlobHash, refusalClaim };
    }
    const refusalClaim = signRefusalClaim(
      {
        authorizationId: input.authorizationId,
        hCommit: input.hCommit,
        reasonCode: input.reasonCode,
        timestamp: input.timestamp,
      },
      input.signingKeyPem,
    );
    const txHash = await input.registry.refusePublic(
      input.authorizationId,
      input.hCommit,
      input.reasonCode,
      input.proofRef,
    );
    return { signed: false, txHash, refusalClaim };
  }
  if (input.reasonCode === RefusalCode.OptOutActive) {
    const refusalClaim = signRefusalClaim(
      {
        authorizationId: input.authorizationId,
        hCommit: input.hCommit,
        reasonCode: input.reasonCode,
        timestamp: input.timestamp,
      },
      input.signingKeyPem,
    );
    const txHash = await input.registry.recordAdvisorySignal(
      input.authorizationId,
      input.hCommit,
      input.reasonCode,
    );
    return { signed: true, txHash, refusalClaim };
  }
  throw new Error(`invalid G4 refusal code 0x${input.reasonCode.toString(16).padStart(2, "0")}`);
}

export function isBlocking(code: number): boolean {
  return code >= RefusalCode.LegalCompel && code <= RefusalCode.OracleDeprecated;
}
