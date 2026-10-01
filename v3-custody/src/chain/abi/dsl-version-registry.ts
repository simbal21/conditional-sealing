// Trimmed ABI for `DSLVersionRegistry`. Source: M2 ABI JSON.

export const dslVersionRegistryAbi = [
  {
    type: "function",
    name: "getEntryAt",
    inputs: [
      { name: "id", type: "bytes32", internalType: "bytes32" },
      { name: "blockNumber", type: "uint64", internalType: "uint64" },
    ],
    outputs: [{ name: "encodedEntry", type: "bytes", internalType: "bytes" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "deprecationFlag",
    inputs: [{ name: "id", type: "bytes32", internalType: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "deprecated", type: "bool", internalType: "bool" },
          { name: "reasonCode", type: "uint8", internalType: "uint8" },
          { name: "disclosureCid", type: "bytes32", internalType: "bytes32" },
          { name: "disclosureCommitHash", type: "bytes32", internalType: "bytes32" },
        ],
      },
    ],
    stateMutability: "view",
  },
] as const;
