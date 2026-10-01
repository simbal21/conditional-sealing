import type { Address, Hex, WalletClient } from "viem";

export const DISCLOSURE_VERIFIER_REGISTRY_ABI = [
  {
    type: "function",
    name: "registerVerifierContract",
    stateMutability: "nonpayable",
    inputs: [
      { name: "verifierRef", type: "bytes32" },
      { name: "verifierContract", type: "address" },
    ],
    outputs: [],
  },
] as const;

export interface VerifierRegistration {
  readonly verifierRef: Hex;
  readonly verifierContract: Address;
}

export async function registerVerifierContracts(
  walletClient: WalletClient,
  disclosureRegistryAddress: Address,
  registrations: readonly VerifierRegistration[],
): Promise<readonly Hex[]> {
  const hashes: Hex[] = [];
  const writeContract = walletClient.writeContract as (parameters: {
    address: Address;
    abi: typeof DISCLOSURE_VERIFIER_REGISTRY_ABI;
    functionName: "registerVerifierContract";
    args: readonly [Hex, Address];
  }) => Promise<Hex>;
  for (const registration of registrations) {
    const hash = await writeContract({
      address: disclosureRegistryAddress,
      abi: DISCLOSURE_VERIFIER_REGISTRY_ABI,
      functionName: "registerVerifierContract",
      args: [registration.verifierRef, registration.verifierContract],
    });
    hashes.push(hash);
  }
  return hashes;
}
