export interface SdkVersionManifest {
  readonly packages: readonly {
    readonly name: string;
    readonly semver: string;
    readonly integrity_hash: string;
    readonly lockfile_ref: string;
    readonly release_signature_ref: string;
  }[];
  readonly compatibility: {
    readonly api_version: string;
    readonly bundle_version: string;
    readonly commit_version: string;
  };
}

export function getSdkVersionManifest(): SdkVersionManifest {
  return {
    packages: [
      {
        name: "@cealis/verify-sdk",
        semver: "0.1.0",
        integrity_hash: "stage3-local-build",
        lockfile_ref: "pnpm-lock.yaml",
        release_signature_ref: "stage3-release-manifest",
      },
    ],
    compatibility: {
      api_version: "1.0-draft",
      bundle_version: "s2-5.1",
      commit_version: "0x0302",
    },
  };
}
