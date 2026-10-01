import { ROOT_BINDING_LEVEL, SdSdkError, SdSdkErrorCode, ZERO_HEX_32, type EscrowCommitReference, type PdaSdConfig, type SdBindingMode, type SdBundle } from "./types.js";

export function verifyBindingMode(escrowCommit: EscrowCommitReference, pdaSdConfig: PdaSdConfig, sdBundle?: SdBundle): SdBindingMode {
  if (escrowCommit.commit_version !== "0x0302") throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);
  const aadRoot = normalizeHex32(escrowCommit.commit_AAD.sdMerkleRoot);
  if (pdaSdConfig.ingestion_mode === "MODE_B" && pdaSdConfig.sd_enabled) {
    throw new SdSdkError(SdSdkErrorCode.CONFIG_MODE_B_INCOMPATIBLE);
  }

  if (!pdaSdConfig.sd_enabled) {
    if (aadRoot !== ZERO_HEX_32) throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);
    if (sdBundle && sdBundle.status !== "not_configured") throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);
    return "sd_disabled";
  }

  if (!sdBundle) throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);
  if (sdBundle.rootBindingLevel !== ROOT_BINDING_LEVEL) throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);

  const bundleRoot = normalizeHex32(sdBundle.sdMerkleRoot ?? ZERO_HEX_32);
  if (aadRoot === ZERO_HEX_32 && sdBundle.status === "failed" && bundleRoot === ZERO_HEX_32) return "sd_failed_before_root";
  if (aadRoot === ZERO_HEX_32 || bundleRoot === ZERO_HEX_32 || aadRoot !== bundleRoot) {
    throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);
  }
  return "sd_enabled";
}

function normalizeHex32(value: string): string {
  const lower = value.toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(lower)) throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);
  return lower;
}

