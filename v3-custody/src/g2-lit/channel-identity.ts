import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";

export interface LitChannelIdentityInput {
  readonly endpointUrl: string;
  readonly certificatePinSha256: string;
  readonly observedCertificateSha256?: string;
  readonly mtlsClientCertificateSha256?: string;
  readonly requiredTeeChannelId?: string;
  readonly observedTeeChannelId?: string;
}

export function verifyLitChannelIdentity(input: LitChannelIdentityInput): void {
  const url = new URL(input.endpointUrl);
  if (url.protocol !== "https:") {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
      "Lit channel must use HTTPS/TLS 1.3 capable transport",
    );
  }
  if (!/^sha256:[0-9a-f]{64}$/i.test(input.certificatePinSha256)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
      "Lit vendor certificate pin is missing or malformed",
    );
  }
  if (
    input.observedCertificateSha256 !== undefined &&
    input.observedCertificateSha256.toLowerCase() !== input.certificatePinSha256.toLowerCase()
  ) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
      "Lit channel certificate pin mismatch",
    );
  }
  if (input.mtlsClientCertificateSha256 !== undefined && !/^sha256:[0-9a-f]{64}$/i.test(input.mtlsClientCertificateSha256)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
      "Lit mTLS client certificate fingerprint is malformed",
    );
  }
  if (
    input.requiredTeeChannelId !== undefined &&
    input.observedTeeChannelId !== undefined &&
    input.requiredTeeChannelId !== input.observedTeeChannelId
  ) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE,
      "Lit TEE channel identity mismatch",
    );
  }
}
