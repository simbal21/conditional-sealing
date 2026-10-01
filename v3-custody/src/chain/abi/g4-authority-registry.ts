// Trimmed ABI for `G4AuthorityRegistry` — read-only surface used by
// the V3 SDK. Source: `contracts/out/G4AuthorityRegistry.sol/
// G4AuthorityRegistry.json`.
//
// `getG4AuthorityAt(g4AuthorityRef, blockNumber)` returns an opaque
// `tuple` whose components are inferred from the spec — the M2 ABI
// declares the return as `(bytes32 outputs)` for class-CRYPTO entries
// (the registry stores `encodedEntry` which the SDK decodes downstream).
// The SDK uses `getEntryAt` to receive the raw encoded bytes and
// decodes per internal design record `v3-registry-class-discipline.md`.

export const g4AuthorityRegistryAbi = [
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
  {
    type: "event",
    name: "EntryAdded",
    inputs: [
      { name: "id", type: "bytes32", indexed: false },
      { name: "effectiveBlock", type: "uint64", indexed: false },
    ],
  },
  {
    type: "event",
    name: "EntryTombstoned",
    inputs: [
      { name: "id", type: "bytes32", indexed: false },
      { name: "tombstoneBlock", type: "uint64", indexed: false },
    ],
  },
  {
    type: "event",
    name: "DeprecationFlagSet",
    inputs: [
      { name: "id", type: "bytes32", indexed: false },
      { name: "reasonCode", type: "uint8", indexed: false },
      { name: "disclosureCid", type: "bytes32", indexed: false },
      { name: "disclosureCommitHash", type: "bytes32", indexed: false },
    ],
  },
] as const;
