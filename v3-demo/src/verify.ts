// @cealis/v3-demo/verify.ts — round-aware wrapper over @cealis/verify-sdk.
//
// The verify-sdk runs OFFLINE — independence is a normative property per
// S2-5 §4.7 + §9.1. Round 1 + 3 verify their bundles with the partner-
// supplied RPC (Anvil in CI, real Base Sepolia in live mode). Round 2 has
// no bundle to verify (no RevealAuthorized fired). Round 2b verifies the
// refusal artifact format using SD-aware checks.

import { verifyArtifactBundle, verifyWebhook } from "@cealis/verify-sdk";
import type {
  RevealArtifactBundle,
  VerifyArtifactOptions,
  VerifyArtifactResult,
} from "@cealis/verify-sdk";
import { getChainConfig, type DemoMode, getMode } from "./setup.js";

export interface DemoVerifyInput {
  readonly bundle: RevealArtifactBundle;
  readonly mode?: DemoMode;
  /**
   * Override the partner RPC URL — defaults to the demo mode's chain RPC.
   */
  readonly chainRpcUrlOverride?: string;
  readonly expectedRecipientRef?: string;
  readonly now?: Date;
}

/**
 * Round 1 / Round 3 verification: pass `mode` to use the partner-controlled
 * RPC (mock in CI, real Base Sepolia in live). Independence preserved:
 * verify-sdk does NOT call any Cealis-controlled endpoint.
 */
export async function verifyRoundBundle(input: DemoVerifyInput): Promise<VerifyArtifactResult> {
  const mode = input.mode ?? getMode();
  const config = getChainConfig(mode);
  const options: VerifyArtifactOptions = {
    chainRpcUrl: input.chainRpcUrlOverride ?? config.rpcUrl,
    now: input.now,
    expectedRecipientRef: input.expectedRecipientRef,
    requireOnlineRegistryChecks: false,
  };
  return await verifyArtifactBundle(input.bundle, options);
}

/**
 * Webhook verification helper for round-end delivery assertions. M5 webhook
 * deliveries are independently verifiable by partners; we exercise the
 * partner path in CI to confirm webhook payload + signature pair.
 */
export async function verifyDemoWebhook(input: {
  readonly rawBody: Uint8Array;
  readonly headers: {
    "x-cealis-timestamp": string;
    "x-cealis-signature": string;
    "x-cealis-event": string;
    "x-cealis-delivery": string;
  };
  readonly secret: Uint8Array;
  readonly now?: Date;
}): Promise<{ overall: "pass" | "fail" | "skipped" }> {
  const result = await verifyWebhook(input.rawBody, input.headers, input.secret, input.now);
  return { overall: result.overall };
}
