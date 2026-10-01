# @cealis/verify-sdk

## Status (at retirement, June 2026)

**STUB.** This package was never functional and must not be described as working.

Offline verification SDK for Cealis V3 reveal artifacts. Per `docs/specs/ingestion-delivery-api-spec.md` §4.7 + §9.1 + App. B.

## Independence (NORMATIVE)

This package has **zero Cealis-network dependency**. Verification works against a partner-supplied RPC URL for chain reads only. Verifying a `RevealArtifactBundle` does not require Cealis API to be reachable.

Forbidden inside this package:
- No `axios` / `node-fetch` / Cealis API URL
- No `@cealis/v3-api` import
- No `@cealis/v3-custody` import
- No Postgres / Redis / BullMQ / Fastify

Allowed:
- `@cealis/v3-crypto` (workspace:* — σ verifier primitives, TAG constants)
- `@noble/hashes` (HMAC + keccak)
- `canonicalize` (RFC 8785 JCS)
- `viem` (partner-supplied chain RPC reads)

## Three primary functions

```ts
import { verifyArtifactBundle, verifySdOutput, verifyWebhook } from "@cealis/verify-sdk";

// Bundle verification (15 named checks + overall discriminator)
const result = await verifyArtifactBundle(bundle, {
  chainRpcUrl: "https://my-partner-rpc/...", // partner-supplied
  requireOnlineRegistryChecks: true,
});

// SD output verification (selective disclosure cleartext + ZK proofs)
const sdResult = await verifySdOutput(sd);

// Webhook signature verification (HMAC over `utf8(timestamp) "." rawBody` BEFORE JSON.parse)
const webhookResult = await verifyWebhook(rawBody, headers, secret);
```

## Where the build stopped

An earlier version of this section described the Phase A skeleton (stubs throwing `not_implemented`). The code moved past that: the 15 named bundle checks are wired in `src/verify-artifact-bundle.ts`, and the suite was 102/102 green on the 2026-07-03 fresh-install verification, including an offline-independence test.

The root README still grades this package **stub**, and that verdict stands — it is the frozen state-at-retirement assessment, and it is about the guarantee, not the source: the independence property was never delivered or validated as a shippable, externally consumed SDK. No partner ever ran it, and nobody maintains it. Read this code as evidence of the design, not as a supported verifier.
