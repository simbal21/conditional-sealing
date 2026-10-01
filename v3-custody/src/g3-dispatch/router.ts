import type {
  HealthProbeResult,
  PrepareCommitBindingInput,
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "../adapters/gate-adapter.js";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
  type CustodyErrorCode,
} from "../errors.js";
import {
  decodeCommitAAD,
  G3_CHOICE,
} from "../m1-imports.js";
import type {
  DrandAdapter,
  DrandPrepareExtras,
  DrandRequestExtras,
  DrandKemPubkey,
  SigmaG3,
} from "../g3-drand/index.js";
import type {
  DcipherAdapter,
  DcipherPrepareExtras,
  DcipherRequestExtras,
  DcipherKemPubkey,
  SigmaG3Dcipher,
} from "../g3-dcipher/index.js";
import {
  getDcipherExclusionReason,
  isDcipherIncluded,
} from "./build-time-exclusion.js";

export type G3Choice = 0 | 1;

export interface G3Adapters {
  readonly drand: DrandAdapter;
  readonly dcipher?: DcipherAdapter;
  readonly isDcipherIncluded?: () => boolean;
  readonly getDcipherExclusionReason?: () => string | null;
}

export type G3DispatchOperation =
  | {
      readonly kind: "prepareCommitBinding";
      readonly input: PrepareCommitBindingInput<DrandPrepareExtras | DcipherPrepareExtras>;
    }
  | {
      readonly kind: "requestSigma";
      readonly input: RequestSigmaInput<DrandRequestExtras | DcipherRequestExtras>;
    }
  | {
      readonly kind: "verifySigma";
      readonly input: RequestSigmaInput<DrandRequestExtras | DcipherRequestExtras> & {
        readonly sigma: SigmaG3 | SigmaG3Dcipher;
      };
    }
  | { readonly kind: "healthProbe" };

export type G3DispatchValue =
  | DrandKemPubkey
  | DcipherKemPubkey
  | (RequestSigmaResult & { sigma: SigmaG3 | SigmaG3Dcipher })
  | VerifySigmaResult
  | HealthProbeResult;

export type G3DispatchResult =
  | {
      readonly ok: true;
      readonly g3Choice: G3Choice;
      readonly value: G3DispatchValue;
    }
  | {
      readonly ok: false;
      readonly g3Choice?: G3Choice;
      readonly code: CustodyErrorCode;
      readonly detail: string;
    };

export async function dispatchG3(
  commitAAD: Uint8Array,
  adapters: G3Adapters,
  operation: G3DispatchOperation,
): Promise<G3DispatchResult> {
  const choice = readG3Choice(commitAAD);
  if (!choice.ok) return choice;

  try {
    if (choice.g3Choice === G3_CHOICE.DCIPHER) {
      const included = adapters.isDcipherIncluded?.() ?? isDcipherIncluded();
      if (!included || adapters.dcipher === undefined) {
        return {
          ok: false,
          g3Choice: G3_CHOICE.DCIPHER,
          code: CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED,
          detail:
            adapters.getDcipherExclusionReason?.() ??
            getDcipherExclusionReason() ??
            "dcipher adapter excluded from this build",
        };
      }
      return {
        ok: true,
        g3Choice: G3_CHOICE.DCIPHER,
        value: await runDcipher(adapters.dcipher, operation),
      };
    }

    return {
      ok: true,
      g3Choice: G3_CHOICE.DRAND,
      value: await runDrand(adapters.drand, operation),
    };
  } catch (err) {
    if (err instanceof CustodyError) {
      return {
        ok: false,
        g3Choice: choice.g3Choice,
        code: err.code,
        detail: err.message,
      };
    }
    return {
      ok: false,
      g3Choice: choice.g3Choice,
      code: CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL,
      detail: err instanceof Error ? err.message : "unknown G3 dispatch failure",
    };
  }
}

export function readG3Choice(
  commitAAD: Uint8Array,
):
  | { readonly ok: true; readonly g3Choice: G3Choice }
  | {
      readonly ok: false;
      readonly code: CustodyErrorCode;
      readonly detail: string;
    } {
  try {
    const decoded = decodeCommitAAD(commitAAD);
    if (decoded.g3_choice === G3_CHOICE.DCIPHER) {
      return { ok: true, g3Choice: G3_CHOICE.DCIPHER };
    }
    if (decoded.g3_choice === G3_CHOICE.DRAND) {
      return { ok: true, g3Choice: G3_CHOICE.DRAND };
    }
    return {
      ok: false,
      code: CUSTODY_ERROR_CODES.CUSTODY_ERR_MODE3_RESERVED,
      detail: `unsupported g3_choice ${decoded.g3_choice}`,
    };
  } catch (err) {
    return {
      ok: false,
      code: CUSTODY_ERROR_CODES.CUSTODY_ERR_MODE3_RESERVED,
      detail: err instanceof Error ? err.message : "commit_AAD decode failed",
    };
  }
}

async function runDrand(
  adapter: DrandAdapter,
  operation: G3DispatchOperation,
): Promise<G3DispatchValue> {
  switch (operation.kind) {
    case "prepareCommitBinding":
      return adapter.prepareCommitBinding(
        operation.input as PrepareCommitBindingInput<DrandPrepareExtras>,
      );
    case "requestSigma":
      return adapter.requestSigma(
        operation.input as RequestSigmaInput<DrandRequestExtras>,
      );
    case "verifySigma":
      return adapter.verifySigma(
        operation.input as RequestSigmaInput<DrandRequestExtras> & { sigma: SigmaG3 },
      );
    case "healthProbe":
      return adapter.healthProbe();
  }
}

async function runDcipher(
  adapter: DcipherAdapter,
  operation: G3DispatchOperation,
): Promise<G3DispatchValue> {
  switch (operation.kind) {
    case "prepareCommitBinding":
      return adapter.prepareCommitBinding(
        operation.input as PrepareCommitBindingInput<DcipherPrepareExtras>,
      );
    case "requestSigma":
      return adapter.requestSigma(
        operation.input as RequestSigmaInput<DcipherRequestExtras>,
      );
    case "verifySigma":
      return adapter.verifySigma(
        operation.input as RequestSigmaInput<DcipherRequestExtras> & {
          sigma: SigmaG3Dcipher;
        },
      );
    case "healthProbe":
      return adapter.healthProbe();
  }
}
