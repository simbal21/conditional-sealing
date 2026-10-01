import { loadDcipherSdk } from "../g3-dcipher/sdk-loader.js";

export function isDcipherIncluded(): boolean {
  return loadDcipherSdk().included;
}

export function getDcipherExclusionReason(): string | null {
  const load = loadDcipherSdk();
  if (load.included) return null;
  return load.status.status === "deferred"
    ? load.status.reason
    : "dcipher SDK not included";
}
