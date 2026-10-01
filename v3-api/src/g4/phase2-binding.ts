import type { Hex32 } from "../h-commit/index.js";

export interface Phase2Binding {
  readonly quote_digest: Hex32;
  readonly measurement: string;
  readonly user_data_binding_digest: Hex32;
  readonly zkdcap_verifier_ref: string;
}

export function buildPhase2Binding(input: {
  readonly quote_digest: Hex32;
  readonly measurement?: string;
  readonly user_data_binding_digest: Hex32;
  readonly zkdcap_verifier_ref?: string;
}): Phase2Binding {
  return {
    quote_digest: input.quote_digest,
    measurement: input.measurement ?? "phase2-rented-tee-measurement",
    user_data_binding_digest: input.user_data_binding_digest,
    zkdcap_verifier_ref: input.zkdcap_verifier_ref ?? "zkdcap://pending-m8-runtime-ref",
  };
}

