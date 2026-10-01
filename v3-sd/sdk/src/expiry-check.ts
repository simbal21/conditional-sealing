import { SdSdkError, SdSdkErrorCode } from "./types.js";

export function assertClaimNotExpired(expiryTimestamp: number, now: Date): void {
  if (!Number.isSafeInteger(expiryTimestamp) || expiryTimestamp < 0) {
    throw new SdSdkError(SdSdkErrorCode.CLAIM_EXPIRED);
  }
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (expiryTimestamp < nowSeconds) throw new SdSdkError(SdSdkErrorCode.CLAIM_EXPIRED);
}

