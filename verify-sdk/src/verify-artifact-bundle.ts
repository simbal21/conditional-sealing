import type {
  RevealArtifactBundle,
  VerifyArtifactOptions,
  VerifyArtifactResult,
  VerifyCheck,
  VerifyStatus,
} from "./types.js";
import { checkCanonicalization, safeRefsFromBundle, ZERO_HEX32 } from "./checks/canonicalization.js";
import { checkChainProof } from "./checks/chain-proof.js";
import { checkPdaRoot } from "./checks/pda-root.js";
import { checkRegistrySnapshots } from "./checks/registry-snapshots.js";
import { checkEndpointAttestation } from "./checks/endpoint-attestation.js";
import { checkIssuerAttestation } from "./checks/issuer-attestation.js";
import { checkProvenance } from "./checks/provenance.js";
import { checkSigmaSubject } from "./checks/sigma-subject.js";
import { checkSigmaLit } from "./checks/sigma-lit.js";
import { checkSigmaG3 } from "./checks/sigma-g3.js";
import { checkSigmaG4 } from "./checks/sigma-g4.js";
import { checkSigmaConditional } from "./checks/sigma-conditional.js";
import { checkShredState } from "./checks/shred-state.js";
import { checkRecipientSelector } from "./checks/recipient-selector.js";
import { checkSdRefs } from "./checks/sd-refs.js";
import { checkFreshness } from "./checks/freshness.js";

export async function verifyArtifactBundle(
  bundle: RevealArtifactBundle,
  options: VerifyArtifactOptions = {},
): Promise<VerifyArtifactResult> {
  const now = options.now ?? new Date();
  const canonicalization = checkCanonicalization(bundle);
  const context = { options, now };
  const checks = {
    canonicalization: canonicalization.check,
    chainProof: await checkChainProof(bundle, context),
    pdaRoot: checkPdaRoot(bundle),
    registrySnapshots: checkRegistrySnapshots(bundle),
    endpointAttestation: checkEndpointAttestation(bundle),
    issuerAttestation: checkIssuerAttestation(bundle),
    provenance: checkProvenance(bundle),
    sigmaSubject: checkSigmaSubject(bundle),
    sigmaLit: checkSigmaLit(bundle),
    sigmaG3: checkSigmaG3(bundle),
    sigmaG4: checkSigmaG4(bundle),
    sigmaConditional: checkSigmaConditional(bundle),
    shredState: checkShredState(bundle),
    recipientSelector: checkRecipientSelector(bundle, options),
    sdRefs: checkSdRefs(bundle),
    // Security-audit-2026-05-14 TS-API-F-03: blocks artifact-replay attacks.
    // Returns `skipped` unless caller sets maxArtifactAgeSeconds.
    freshness: checkFreshness(bundle, context),
  };

  return {
    overall: overallStatus(Object.values(checks)),
    artifact_bundle_digest: canonicalization.artifactBundleDigest ?? bundle.verification.artifact_bundle_digest ?? ZERO_HEX32,
    checks,
    safe_refs: {
      authorizationId: bundle.authorization.authorizationId,
      h_commit: bundle.authorization.h_commit,
      pda_root: bundle.pda.pda_root,
      authorization_block: bundle.authorization.authorization_block,
    },
  };
}

function overallStatus(checks: readonly VerifyCheck[]): VerifyStatus {
  if (checks.some((check) => check.status === "fail")) return "fail";
  if (checks.every((check) => check.status === "skipped")) return "skipped";
  return "pass";
}

export function artifactSafeRefs(bundle: RevealArtifactBundle): Record<string, string | number | boolean> | undefined {
  return safeRefsFromBundle(bundle) as Record<string, string | number | boolean>;
}
