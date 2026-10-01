import { assertClaimNotExpired } from "./expiry-check.js";
import { assertPublicInputsMatch, recomputePublicInputs } from "./public-input-recompute.js";
import { assertNotRevoked } from "./revocation-client.js";
import { SdSdkError, SdSdkErrorCode, type EscrowCommitReference, type PdaClaimConfig, type PdaSdConfig, type RevocationRegistryClient, type SdBundle, type SdClaimItem, type VerifierRegistryClient } from "./types.js";

export async function verifyClaim(input: {
  readonly sdBundle: SdBundle;
  readonly claimItem: SdClaimItem;
  readonly escrowCommit: EscrowCommitReference;
  readonly pdaSdConfig: PdaSdConfig;
  readonly verifierRegistry: VerifierRegistryClient;
  readonly revocationRegistry: RevocationRegistryClient;
  readonly now: Date;
}): Promise<void> {
  assertClaimNotExpired(input.claimItem.expiry_timestamp, input.now);
  await assertNotRevoked(input.revocationRegistry, input.claimItem.disclosure_id);
  const claimConfig = claimById(input.pdaSdConfig, input.claimItem.claim_id);
  if (!claimConfig) throw new SdSdkError(SdSdkErrorCode.PUBLIC_INPUT_MISMATCH);
  const expected = recomputePublicInputs({ claimConfig, sdBundle: input.sdBundle, escrowCommit: input.escrowCommit, claimItem: input.claimItem });
  assertPublicInputsMatch(input.claimItem.public_inputs, expected);
  const verifier = await input.verifierRegistry.getVerifierAt(input.claimItem.verifier_ref, BigInt(input.escrowCommit.authorizationBlock));
  if (!verifier) throw new SdSdkError(SdSdkErrorCode.PROOF_INVALID);
  if (verifier.publicInputSchemaDigest && claimConfig.public_input_schema_digest && verifier.publicInputSchemaDigest.toLowerCase() !== claimConfig.public_input_schema_digest.toLowerCase()) {
    throw new SdSdkError(SdSdkErrorCode.PROOF_INVALID);
  }
  if (!(await verifier.verifyProof(input.claimItem.proof, input.claimItem.public_inputs))) throw new SdSdkError(SdSdkErrorCode.PROOF_INVALID);
}

function claimById(pda: PdaSdConfig, claimId: string): PdaClaimConfig | undefined {
  return pda.claims.find((claim) => claim.claim_id.toLowerCase() === claimId.toLowerCase());
}

