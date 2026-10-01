import { SigmaBuffer } from "../redaction/sigma-buffer.js";
import { zeroize } from "../redaction/zeroize.js";
import {
  decodeShareRecord,
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_LIT,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  type CommitAADInput,
  type ShareRecord,
  type ShareDomain,
  type ShareRole,
} from "../m1-imports.js";
import { GateKind } from "../types/gate-recipient.js";
import type {
  AccessStructureProfile,
  SigmaEvidence,
  SigmaEvidenceBundle,
} from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import {
  hexToBytes,
  metadataNumber,
  metadataString,
} from "./jcs-canonicalize.js";

export interface AdmittedSigmaEvidence {
  readonly gate: string;
  readonly conditionalRecipientIndex: number;
  readonly sigmaDigest: string;
  readonly stanzaIndex: number;
  readonly share: ShareRecord;
}

export interface SigmaOrchestrationResult {
  readonly admittedShares: readonly ShareRecord[];
  readonly evidence: readonly AdmittedSigmaEvidence[];
}

export function orchestrateSigmas(input: {
  readonly authorizationId: string;
  readonly hCommit: string;
  readonly authorizationBlock: bigint;
  readonly blockHash: string;
  readonly commitAAD: CommitAADInput;
  readonly profile: AccessStructureProfile;
  readonly sigmas: SigmaEvidenceBundle;
}): SigmaOrchestrationResult {
  assertBundleIdentity(input);
  assertFixedOrdering(input.sigmas, input.commitAAD, input.profile);

  const admitted: AdmittedSigmaEvidence[] = [];
  try {
    for (const evidence of input.sigmas.evidence) {
      assertSigmaVerified(evidence);
      const sigma = new SigmaBuffer(evidence.sigmaBytes);
      const share = recoverShareFromEvidence(evidence, input.profile);
      const stanzaIndex = expectedStanzaIndex(evidence, input.commitAAD, input.profile);
      assertStanzaIndex(evidence, stanzaIndex);
      admitted.push({
        gate: gateLabel(evidence.gateKind),
        conditionalRecipientIndex: evidence.conditionalRecipientIndex,
        sigmaDigest: `sha256:${sigma.digestHex}`,
        stanzaIndex,
        share,
      });
      sigma.zeroize();
      zeroize(evidence.sigmaBytes);
    }
    return {
      admittedShares: admitted.map((entry) => entry.share),
      evidence: admitted,
    };
  } catch (error) {
    for (const evidence of input.sigmas.evidence) zeroize(evidence.sigmaBytes);
    if (error instanceof CustodyError) throw error;
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      error instanceof Error ? error.message : "sigma orchestration failed",
      { subCodes: ["ERR_SHARE_UNAUTHORIZED"] },
    );
  }
}

function assertBundleIdentity(input: {
  readonly authorizationId: string;
  readonly hCommit: string;
  readonly authorizationBlock: bigint;
  readonly sigmas: SigmaEvidenceBundle;
}): void {
  if (
    input.sigmas.authorizationId !== input.authorizationId ||
    input.sigmas.hCommit !== input.hCommit ||
    input.sigmas.authorizationBlock !== input.authorizationBlock
  ) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATES_CANNOT_SIGN,
      "SigmaEvidenceBundle identity does not match combine input",
      { subCodes: ["ERR_SIGMA_AUTHORIZATION_CONTEXT_MISMATCH"] },
    );
  }
}

function assertFixedOrdering(
  bundle: SigmaEvidenceBundle,
  commitAAD: CommitAADInput,
  profile: AccessStructureProfile,
): void {
  const required = requiredGateSequence(commitAAD, profile);
  if (bundle.evidence.length < required.length) {
    throw missingBranch("required σ is absent");
  }
  if (bundle.evidence.length > required.length) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      "extra σ not bound by commit profile",
      { subCodes: ["ERR_EXTRA_SIGMA_NOT_BOUND_BY_COMMIT_PROFILE"] },
    );
  }
  const seen = new Set<string>();
  for (let i = 0; i < bundle.evidence.length; i++) {
    const evidence = bundle.evidence[i];
    const expected = required[i];
    if (evidence === undefined || expected === undefined) throw missingBranch("required σ is absent");
    const key = `${evidence.gateKind}:${evidence.conditionalRecipientIndex}`;
    if (seen.has(key)) {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
        "duplicate σ gate evidence",
        { subCodes: ["ERR_DUPLICATE_SIGMA_GATE"] },
      );
    }
    seen.add(key);
    if (
      evidence.gateKind !== expected.gateKind ||
      evidence.conditionalRecipientIndex !== expected.conditionalRecipientIndex
    ) {
      if (
        evidence.gateKind === GateKind.ConditionalRecipient &&
        (
          expected.gateKind === GateKind.LitV3 ||
          expected.gateKind === GateKind.Dcipher ||
          expected.gateKind === GateKind.Drand ||
          expected.gateKind === GateKind.G4
        )
      ) {
        throw missingBranch("mandatory top-level σ is absent");
      }
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
        "σ order does not match fixed policy order",
        { subCodes: ["ERR_SIGMA_ORDER_MISMATCH"] },
      );
    }
  }
}

function requiredGateSequence(
  commitAAD: CommitAADInput,
  profile: AccessStructureProfile,
): readonly { readonly gateKind: GateKind; readonly conditionalRecipientIndex: number }[] {
  const g3Kind = commitAAD.g3_choice === 0 ? GateKind.Dcipher : GateKind.Drand;
  const required: { gateKind: GateKind; conditionalRecipientIndex: number }[] = [
    { gateKind: GateKind.LitV3, conditionalRecipientIndex: 0 },
    { gateKind: g3Kind, conditionalRecipientIndex: 0 },
    { gateKind: GateKind.G4, conditionalRecipientIndex: 0 },
  ];
  if (profile.kind === "RECIPIENT_1_OF_1") {
    required.push({ gateKind: GateKind.ConditionalRecipient, conditionalRecipientIndex: 0 });
  }
  if (profile.kind === "RECIPIENT_K_OF_N") {
    for (let i = 0; i < profile.k_conditional; i++) {
      required.push({ gateKind: GateKind.ConditionalRecipient, conditionalRecipientIndex: i });
    }
  }
  return required;
}

function assertSigmaVerified(evidence: SigmaEvidence): void {
  const verified = metadataString(evidence.metadata, "verified");
  const code = metadataString(evidence.metadata, "verifyCode");
  // Fail-CLOSED: require explicit `verified === "true"`. Previous code passed
  // silently when `verified` was `undefined` (metadata absent) — a σ evidence
  // object with no verification metadata would bypass the combiner's primary
  // gate-authorization check. Security-audit-2026-05-14 TS-CRYPTO-F-06.
  if (verified !== "true" || (code !== undefined && code !== "ok")) {
    throw new CustodyError(
      mapGateFailure(evidence.gateKind),
      "σ verification metadata failed",
      { subCodes: [safeSubCode(code ?? (verified === undefined ? "ERR_SIGMA_VERIFY_METADATA_MISSING" : undefined))] },
    );
  }
}

function recoverShareFromEvidence(
  evidence: SigmaEvidence,
  profile: AccessStructureProfile,
): ShareRecord {
  const encoded = metadataString(evidence.metadata, "shareRecordHex");
  if (encoded !== undefined) {
    return decodeShareRecord(hexToBytes(encoded));
  }
  const shareHex = metadataString(evidence.metadata, "shareHex");
  if (shareHex === undefined) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      "sigma evidence lacks stanza decapsulation share material",
      { subCodes: ["ERR_SHARE_UNAUTHORIZED"] },
    );
  }
  const value = hexToBytes(shareHex);
  if (value.length !== 32) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      "recovered Shamir share must be 32 bytes",
      { subCodes: ["ERR_SHARE_RECORD_VALUE_LENGTH"] },
    );
  }
  return {
    share_domain: shareDomain(evidence, profile),
    share_role: shareRole(evidence, profile),
    logical_index: logicalIndex(evidence, profile),
    x: xCoordinate(evidence, profile),
    value,
  };
}

function shareDomain(evidence: SigmaEvidence, profile: AccessStructureProfile): ShareDomain {
  if (evidence.gateKind !== GateKind.ConditionalRecipient) return SHARE_DOMAIN_TOP_LEVEL;
  if (profile.kind === "RECIPIENT_1_OF_1") return SHARE_DOMAIN_TOP_LEVEL;
  return SHARE_DOMAIN_RECIPIENT_BRANCH;
}

function shareRole(evidence: SigmaEvidence, profile: AccessStructureProfile): ShareRole {
  switch (evidence.gateKind) {
    case GateKind.LitV3:
      return SHARE_ROLE_LIT;
    case GateKind.Dcipher:
    case GateKind.Drand:
      return SHARE_ROLE_G3;
    case GateKind.G4:
      return SHARE_ROLE_G4;
    case GateKind.ConditionalRecipient:
      return profile.kind === "RECIPIENT_1_OF_1"
        ? SHARE_ROLE_RECIPIENT_AGGREGATE
        : SHARE_ROLE_CONDITIONAL_RECIPIENT;
  }
}

function logicalIndex(evidence: SigmaEvidence, profile: AccessStructureProfile): number {
  switch (evidence.gateKind) {
    case GateKind.LitV3:
      return 0;
    case GateKind.Dcipher:
    case GateKind.Drand:
      return 1;
    case GateKind.G4:
      return 2;
    case GateKind.ConditionalRecipient:
      return profile.kind === "RECIPIENT_1_OF_1" ? 3 : evidence.conditionalRecipientIndex;
  }
}

function xCoordinate(evidence: SigmaEvidence, profile: AccessStructureProfile): number {
  return logicalIndex(evidence, profile) + 1;
}

function expectedStanzaIndex(
  evidence: SigmaEvidence,
  commitAAD: CommitAADInput,
  profile: AccessStructureProfile,
): number {
  const sequence = requiredGateSequence(commitAAD, profile);
  const index = sequence.findIndex(
    (item) =>
      item.gateKind === evidence.gateKind &&
      item.conditionalRecipientIndex === evidence.conditionalRecipientIndex,
  );
  if (index < 0) throw missingBranch("σ is not bound by commit profile");
  return index;
}

function assertStanzaIndex(evidence: SigmaEvidence, expected: number): void {
  const actual = metadataNumber(evidence.metadata, "stanzaIndex");
  // Fail-CLOSED: require stanzaIndex to be PRESENT and match expected. Previous
  // version passed silently when stanzaIndex was undefined. Security-audit-2026-05-14
  // TS-CRYPTO-F-06 (same pattern as assertSigmaVerified above).
  if (actual === undefined || actual !== expected) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      "recovered share stanza index does not match commit policy order",
      { subCodes: ["ERR_SHARE_DOMAIN_MISMATCH"] },
    );
  }
}

function mapGateFailure(gateKind: GateKind): keyof typeof CUSTODY_ERROR_CODES {
  switch (gateKind) {
    case GateKind.LitV3:
      return "CUSTODY_ERR_LIT_SIG_INVALID";
    case GateKind.Dcipher:
      return "CUSTODY_ERR_DCIPHER_SIG_INVALID";
    case GateKind.Drand:
      return "CUSTODY_ERR_DRAND_SIG_INVALID";
    case GateKind.G4:
      return "CUSTODY_ERR_G4_REFUSED";
    case GateKind.ConditionalRecipient:
      return "CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET";
  }
}

function gateLabel(gateKind: GateKind): string {
  switch (gateKind) {
    case GateKind.LitV3:
      return "LitV3";
    case GateKind.Dcipher:
      return "Dcipher";
    case GateKind.Drand:
      return "Drand";
    case GateKind.G4:
      return "G4";
    case GateKind.ConditionalRecipient:
      return "ConditionalRecipient";
  }
}

function safeSubCode(code: string | undefined): string {
  if (code === undefined) return "ERR_SHARE_UNAUTHORIZED";
  if (/^(ERR|CUSTODY_ERR|REASON)_[A-Z0-9_]{1,96}$/.test(code)) return code;
  return "ERR_SHARE_UNAUTHORIZED";
}

function missingBranch(message: string): CustodyError {
  return new CustodyError(
    CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
    message,
    { subCodes: ["ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT"] },
  );
}
