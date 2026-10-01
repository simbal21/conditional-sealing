// @cealis/verify-sdk — public surface.
//
// Phase A: types-only barrel + three function STUBS (App. B verbatim signatures).
// Phase E implements bodies + 15-check verifiers + chain-reader + integration tests.
//
// Independence is normative (per S2-5 §4.7 + §9.1). This package MUST NOT import
// @cealis/v3-api, @cealis/v3-custody, axios, node-fetch, or hard-code any Cealis URL.

export * from "./types.js";

export { verifyArtifactBundle } from "./verify-artifact-bundle.js";
export { verifySdOutput } from "./verify-sd-output.js";
export { buildWebhookSignaturePreimage, verifyWebhook } from "./verify-webhook.js";
export { verifyRefusalArtifact } from "./verify-refusal-artifact.js";
