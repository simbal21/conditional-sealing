import type { Hex } from "viem";

/**
 * Vault client interface stub per brief lines 23–24 + 47. The actual vault
 * API lives in M5 — M7 calls it as `vaultClient.deleteCiphertext(hCommit)`
 * during the Step 3 of the §11.3 triple block. Phase A locks the type
 * shape; ceremony scripts in Phase D import this interface and the M8
 * Internal E2E Demo wires a real M5 vault adapter.
 *
 * NOTE: This interface deliberately returns only public verification
 * material (deletion proof + timestamp). Ciphertext bytes never cross the
 * boundary back into v3-ops.
 */
export interface VaultClient {
  /**
   * Delete the ciphertext blob associated with `hCommit` and return the
   * public deletion proof. Failure modes: `VAULT_NOT_FOUND`,
   * `VAULT_DELETE_FORBIDDEN_BY_RETENTION_FLOOR`,
   * `VAULT_ALREADY_DELETED`.
   */
  deleteCiphertext(
    hCommit: Hex,
  ): Promise<{ deletionProof: Hex; timestampUnix: number }>;
  /**
   * Read-only check for existence (used by pre-shred guardrail). Returns
   * `false` if the ciphertext has been deleted or never existed.
   */
  exists(hCommit: Hex): Promise<boolean>;
}

/**
 * Dry-run vault client that records calls without performing them. Phase B/C/D
 * use this for `--dry-run` ceremony execution.
 */
export function makeDryRunVaultClient(): {
  readonly client: VaultClient;
  readonly calls: ReadonlyArray<{
    readonly op: "deleteCiphertext" | "exists";
    readonly hCommit: Hex;
  }>;
} {
  const calls: { op: "deleteCiphertext" | "exists"; hCommit: Hex }[] = [];
  return {
    client: {
      async deleteCiphertext(hCommit: Hex) {
        calls.push({ op: "deleteCiphertext", hCommit });
        return {
          deletionProof:
            ("0x" + "dd".repeat(32)) as Hex,
          timestampUnix: Math.floor(Date.now() / 1000),
        };
      },
      async exists(hCommit: Hex) {
        calls.push({ op: "exists", hCommit });
        return true;
      },
    },
    get calls() {
      return calls;
    },
  };
}
