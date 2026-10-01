// Trimmed ABI for `GateRecipientPubkeyRegistry` — only the read paths
// the V3 SDK exercises. Source: `contracts/out/
// GateRecipientPubkeyRegistry.sol/GateRecipientPubkeyRegistry.json`.
//
// 4-param `getPubkeyAt` per M2 normative ABI (App. A) — see
// SPEC-COMPLIANCE-GUARD-M3 §10.

export const gateRecipientPubkeyRegistryAbi = [
  {
    type: "function",
    name: "getPubkeyAt",
    inputs: [
      { name: "authorizationId", type: "bytes32", internalType: "bytes32" },
      { name: "gateKind", type: "uint8", internalType: "uint8" },
      { name: "conditionalRecipientIndex", type: "uint16", internalType: "uint16" },
      { name: "blockNumber", type: "uint64", internalType: "uint64" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "authorizationId", type: "bytes32", internalType: "bytes32" },
          { name: "gateKind", type: "uint8", internalType: "uint8" },
          {
            name: "conditionalRecipientIndex",
            type: "uint16",
            internalType: "uint16",
          },
          { name: "kemPubkey", type: "bytes", internalType: "bytes" },
          { name: "attestationRef", type: "bytes32", internalType: "bytes32" },
          { name: "effectiveBlock", type: "uint64", internalType: "uint64" },
          { name: "tombstoneBlock", type: "uint64", internalType: "uint64" },
          { name: "perCommitEphemeral", type: "bool", internalType: "bool" },
        ],
      },
    ],
    stateMutability: "view",
  },
] as const;
