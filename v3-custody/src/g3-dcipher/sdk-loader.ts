import { createRequire } from "node:module";

export interface DcipherSdkDeferredStatus {
  readonly status: "deferred";
  readonly reason: string;
  readonly expectedPackage: string;
}

export interface DcipherSdkPinnedStatus {
  readonly status: "pinned";
  readonly packageName: string;
  readonly version: string;
  readonly resolvedPath: string;
}

export type DcipherSdkStatus = DcipherSdkDeferredStatus | DcipherSdkPinnedStatus;

export interface DcipherSdkLoadResult {
  readonly included: boolean;
  readonly status: DcipherSdkStatus;
  readonly sdk?: unknown;
}

const DCIPHER_PACKAGE = "@randamu/dcipher-sdk";

export function loadDcipherSdk(): DcipherSdkLoadResult {
  const flag = process.env.CEALIS_DCIPHER_SDK_PRESENT;
  if (flag === "false") return deferred("CEALIS_DCIPHER_SDK_PRESENT=false");

  const req = createRequire(import.meta.url);
  try {
    const resolvedPath = req.resolve(DCIPHER_PACKAGE);
    if (flag === "false") return deferred("feature flag disabled after resolve");
    const packageJson = req(`${DCIPHER_PACKAGE}/package.json`) as {
      version?: unknown;
    };
    const version =
      typeof packageJson.version === "string" && packageJson.version.length > 0
        ? packageJson.version
        : "unknown";
    return {
      included: true,
      status: {
        status: "pinned",
        packageName: DCIPHER_PACKAGE,
        version,
        resolvedPath,
      },
      sdk: req(DCIPHER_PACKAGE) as unknown,
    };
  } catch {
    return deferred(
      flag === "true"
        ? "CEALIS_DCIPHER_SDK_PRESENT=true but @randamu/dcipher-sdk is not resolvable"
        : "Randamu dcipher SDK not present in node_modules; drand-only build",
    );
  }
}

export function isDcipherSdkIncluded(): boolean {
  return loadDcipherSdk().included;
}

function deferred(reason: string): DcipherSdkLoadResult {
  return {
    included: false,
    status: {
      status: "deferred",
      reason,
      expectedPackage: DCIPHER_PACKAGE,
    },
  };
}
