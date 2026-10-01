# `@cealis/verify-sdk` — Vendor Confirmation

Stage-3 M5 ship state recorded 2026-05-11. The verify SDK is a separately-published package because **independence is a security property** per S2-5 §4.7 + §9.1: a partner verifying a Cealis artifact must not need to call any Cealis service.

## Locked dependencies (zero-network policy)

| Dep | Pin | Purpose |
|---|---|---|
| `@cealis/v3-crypto` | `workspace:*` | σ verifier primitives + AEAD + JCS helpers + tag constants |
| `viem@2.21.55` | matched to M3/M4 | Decode `RevealAuthorized` event from **partner-supplied** RPC |
| `canonicalize@2.0.0` | matched to M3/M4 | RFC 8785 JCS bundle digest verification |
| `@noble/hashes@1.8.0` | matched to M3/M4 | HMAC + SHA-256 for webhook signature verification |

**Forbidden dep classes** (asserted in `tests/foundation/no-network-deps.test.ts`):

- No HTTP client (`axios`, `node-fetch`, `undici`, `got`)
- No Cealis-API SDK (`@cealis/v3-api`, `@cealis/v3-custody`)
- No queue / DB (`bullmq`, `pg`, `drizzle-orm`)
- No Cealis URL constants anywhere in source

The SDK accepts a partner-supplied RPC URL for chain reads — Cealis never sees the verification path.

## Three public functions (per App. B)

| Function | What it verifies | Where |
|---|---|---|
| `verifyArtifactBundle` | 15 named checks per App. B + `overall` discriminator | `src/verify-artifact-bundle.ts` |
| `verifySdOutput` | Per-field Poseidon BN254 commitment + sdMerkleRoot + per-field PLONK proof | `src/verify-sd-output.ts` |
| `verifyWebhook` | HMAC over `utf8(timestamp) "." raw_body` **BEFORE** `JSON.parse` (per §7.5 parser-differential discipline) + 300s replay window | `src/verify-webhook.ts` |

## 15 named artifact checks (each its own module)

`canonicalization · chainProof · pdaRoot · registrySnapshots · endpointAttestation · issuerAttestation · provenance · sigmaSubject · sigmaLit · sigmaG3 · sigmaG4 · sigmaConditional · shredState · recipientSelector · sdRefs` + `overall: VerifyStatus` discriminator. Verbatim from App. B lines 2636-2652. Each check returns a structured result with `code` field; `overall` aggregates.

## Test surface

- **5 test files** / **96.17% coverage** (target ≥95%)
- `verify-artifact-bundle.test.ts` — happy path + each check failure mode
- `verify-sd-output.test.ts` — SD proof verification + revocation check
- `verify-webhook.test.ts` — HMAC-before-JSON-parse + replay window + malformed-signature/timestamp paths
- `all-15-checks.test.ts` — each of the 15 checks exercised in isolation
- `offline-independence.test.ts` — Cealis API mocked unreachable; SDK still verifies via partner RPC

## Anti-drift assertions

- Zero network deps in `package.json` (foundation test asserts)
- Zero Cealis URL strings in source (Phase F tripwire grep #4)
- `verifyWebhook` always extracts HMAC before invoking `JSON.parse` (test asserts parser-differential path)
- Chain reader implementation rejects any Cealis-hosted RPC URL pattern; only partner-supplied URLs accepted
