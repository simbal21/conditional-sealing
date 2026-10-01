export interface NetworkVerificationManifest {
  readonly chain_id: number;
  readonly condition_engine_address: string;
  readonly shred_registry_address: string;
  readonly g4_refusal_registry_address: string;
  readonly registry_contracts: Record<string, string>;
  readonly disclosure_registry_address: string;
  readonly plonk_verifier_address: string;
  readonly deployment_block: number;
  readonly bytecode_hashes: Record<string, string>;
  readonly version_label: string;
  readonly governance_owner_ref: string;
}

export function getNetworkVerificationManifest(): { networks: readonly NetworkVerificationManifest[] } {
  return {
    networks: [
      {
        chain_id: 84532,
        condition_engine_address: "0x0000000000000000000000000000000000000001",
        shred_registry_address: "0x0000000000000000000000000000000000000002",
        g4_refusal_registry_address: "0x0000000000000000000000000000000000000003",
        registry_contracts: {
          pda_registry: "0x0000000000000000000000000000000000000004",
          condition_module_registry: "0x0000000000000000000000000000000000000005",
        },
        disclosure_registry_address: "0x0000000000000000000000000000000000000006",
        plonk_verifier_address: "0x0000000000000000000000000000000000000007",
        deployment_block: 0,
        bytecode_hashes: {
          condition_engine: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        version_label: "s2-5.1-stage3-local",
        governance_owner_ref: "cealis-stage3-release-manifest",
      },
    ],
  };
}
