import type { ErrorCodeKey } from "../errors/index.js";
import { throwProblem } from "../errors/index.js";
import type { OperationalClass } from "../types/index.js";
import type { AttestationPreflight } from "./attestation-builder.js";
import { PHASE_1_TRUST_STATEMENT } from "./phase1-binding.js";

export interface PhasePolicyInput {
  readonly g4_phase: 1 | 2;
  readonly operational_class: OperationalClass;
  readonly partner_ready: boolean;
  readonly legal_effect_expected: boolean;
}

export function isPhase1AllowedForNewCommit(input: PhasePolicyInput): boolean {
  return (
    input.g4_phase === 2 ||
    (input.operational_class === "consumer" &&
      input.partner_ready === false &&
      input.legal_effect_expected === false)
  );
}

export function enforceG4PhasePolicy(input: PhasePolicyInput, correlationId: string): void {
  if (isPhase1AllowedForNewCommit(input)) return;
  throwProblem("GOVERNANCE_PHASE_1_REJECTED_FOR_PARTNER_READY", correlationId, {
    detail: "PDA inspection returned Phase 1 for a partner-ready or legal-effect commit path",
    safe_refs: {},
    retryable: false,
  });
}

function checkFailed(preflight: AttestationPreflight): ErrorCodeKey | undefined {
  const checks = preflight.verification_checks;
  if (checks.lit_assignment.status !== "pass") return "ATTESTATION_LIT_ASSIGNMENT_MISSING";
  if (checks.lit_dcap.status !== "pass") return "ATTESTATION_DCAP_INVALID";
  if (checks.g3_pubkey.status !== "pass") return "ATTESTATION_G3_PUBKEY_INVALID";
  if (checks.g4_authority.status !== "pass") return "ATTESTATION_G4_AUTHORITY_INVALID";
  return undefined;
}

export function verifyAttestationPreflightOrThrow(
  preflight: AttestationPreflight,
  expected: {
    readonly authorizationIdCandidate: string;
    readonly preflight_context_digest: string;
    readonly commit_block_number: number;
    readonly commit_block_hash: string;
    readonly client_attestation_digest: string;
    readonly header_attestation_digest: string;
  },
  correlationId: string,
): void {
  const failed = checkFailed(preflight);
  if (failed !== undefined) {
    throwProblem(failed, correlationId, {
      detail: "Client pre-flight attestation contained a failed four-check result",
      safe_refs: { authorizationId: expected.authorizationIdCandidate },
      retryable: false,
    });
  }

  const sameContext =
    preflight.authorizationIdCandidate === expected.authorizationIdCandidate &&
    preflight.preflight_context_digest === expected.preflight_context_digest &&
    preflight.commit_block_number === expected.commit_block_number &&
    preflight.commit_block_hash === expected.commit_block_hash;
  const sameDigest =
    preflight.digest === expected.client_attestation_digest &&
    expected.header_attestation_digest === expected.client_attestation_digest;

  if (!sameContext || !sameDigest) {
    throwProblem("ATTESTATION_DCAP_INVALID", correlationId, {
      detail: "Pre-flight attestation digest or commit-block binding did not match the submitted context",
      safe_refs: { authorizationId: expected.authorizationIdCandidate },
      retryable: false,
    });
  }

  if (
    preflight.g4_authority.phase === 1 &&
    preflight.g4_authority.phase1?.phase_trust_statement !== PHASE_1_TRUST_STATEMENT
  ) {
    throwProblem("ATTESTATION_G4_AUTHORITY_INVALID", correlationId, {
      detail: "Phase 1 G4 authority evidence did not carry the registered-binary trust statement",
      safe_refs: { authorizationId: expected.authorizationIdCandidate },
      retryable: false,
    });
  }
}

