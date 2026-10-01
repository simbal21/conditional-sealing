import { ErrorCode } from "../errors/codes.js";
import { HttpProblem, problemFromCode } from "../errors/problem.js";
import type { Hex32, RevealArtifactBundle } from "../types/reveal-artifact-bundle.js";
import { jcsDigest, toJcsValue } from "./canonicalize-jcs.js";

export interface RecipientSelector {
  readonly recipient_ref: string;
  readonly recipient_pubkey_id?: string;
  readonly schema_selector_digest: Hex32;
  readonly fields: readonly string[];
}

export type RecipientPlaintext = RevealArtifactBundle["plaintext"];

export function applyRecipientSelector(input: {
  readonly fullPlaintext: Readonly<Record<string, unknown>>;
  readonly schema_digest: Hex32;
  readonly selector: RecipientSelector;
  readonly correlation_id?: string;
}): RecipientPlaintext {
  const selected: Record<string, unknown> = {};
  const hashes: Record<string, Hex32> = {};

  for (const field of input.selector.fields) {
    if (!Object.prototype.hasOwnProperty.call(input.fullPlaintext, field)) {
      throw new HttpProblem(
        problemFromCode("COMBINER_RECIPIENT_SELECTOR_INVALID", input.correlation_id ?? input.selector.recipient_ref, {
          detail: ErrorCode.COMBINER_RECIPIENT_SELECTOR_INVALID.title,
          safe_refs: {},
          retryable: false,
        }),
      );
    }
    const value = input.fullPlaintext[field];
    selected[field] = value;
    hashes[field] = jcsDigest(toJcsValue(value));
  }

  return {
    schema_selector_digest: input.selector.schema_selector_digest,
    schema_digest: input.schema_digest,
    content_encoding: "application/json",
    fields: selected,
    field_hashes: hashes,
  };
}

export function buildArtifactRecipient(
  selector: RecipientSelector,
): RevealArtifactBundle["recipient"] {
  return {
    recipient_ref: selector.recipient_ref,
    ...(selector.recipient_pubkey_id === undefined
      ? {}
      : { recipient_pubkey_id: selector.recipient_pubkey_id }),
    schema_selector_digest: selector.schema_selector_digest,
  };
}
