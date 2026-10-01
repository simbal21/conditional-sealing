import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

const textEncoder = new TextEncoder();

export interface PreSigmaPayloadInput {
  readonly token: string;
  readonly partner_id: string;
  readonly pda_id: string;
  readonly pda_version: string;
  readonly condition_summary: string;
  readonly shred_summary: string;
  readonly schema_digest: string;
  readonly h_commit_inputs?: Record<string, string | number | boolean>;
  readonly recipients?: readonly Record<string, string>[];
}

export interface PreSigmaPayload {
  readonly token: string;
  readonly partner_id: string;
  readonly pda_id: string;
  readonly pda_version: string;
  readonly condition_module_summary: string;
  readonly shred_logic_summary: string;
  readonly schema_digest: string;
  readonly h_commit_inputs: Record<string, string | number | boolean>;
  readonly recipients: readonly Record<string, string>[];
  readonly subject_signing_challenge: string;
  readonly confirmation_checklist: readonly string[];
  readonly payload_digest: string;
}

export function buildPreSigmaPayload(input: PreSigmaPayloadInput): PreSigmaPayload {
  const core = {
    token: input.token,
    partner_id: input.partner_id,
    pda_id: input.pda_id,
    pda_version: input.pda_version,
    condition_module_summary: input.condition_summary,
    shred_logic_summary: input.shred_summary,
    schema_digest: input.schema_digest,
    h_commit_inputs: input.h_commit_inputs ?? {},
    recipients: input.recipients ?? [],
    confirmation_checklist: [
      "condition_module_reviewed",
      "shred_posture_reviewed",
      "recipient_set_reviewed",
      "schema_digest_reviewed",
    ],
  } as const;
  const subjectSigningChallenge = bytesToHex(
    sha256(textEncoder.encode(`${core.partner_id}:${core.pda_id}:${core.schema_digest}:${input.token}`)),
  );
  const payloadDigest = bytesToHex(sha256(textEncoder.encode(JSON.stringify(core))));
  return {
    ...core,
    subject_signing_challenge: subjectSigningChallenge,
    payload_digest: payloadDigest,
  };
}
