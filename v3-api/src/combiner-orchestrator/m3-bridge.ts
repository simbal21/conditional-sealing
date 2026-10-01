import * as M3 from "../m3-imports.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

export const REQUIRED_M3_COMBINER_EXPORTS = [
  "runPreVerifyPipeline",
  "orchestrateSigmas",
  "reconstructFileKey",
  "combineAndDecrypt",
  "verifyRegistrySnapshots",
  "verifyGateRecipientPubkeys",
  "verifyPluginIntegrity",
  "assertCrossVendorTeeDisjoint",
  "assertShredStateSignable",
  "verifySupersessionLineage",
  "applyRuntimeHardening",
  "dispatchProfile",
  "rejectMode3",
  "assembleRevealArtifactBundle",
  "jcsCanonicalize",
  "jcsDigest",
  "decryptAeadPayload",
] as const;

export type M3CombinerInput = Parameters<typeof M3.combineAndDecrypt>[0];
export type M3LowLevelArtifactInput = Parameters<typeof M3.assembleRevealArtifactBundle>[0];
export type M3LowLevelArtifactResult = ReturnType<typeof M3.assembleRevealArtifactBundle>;

export interface M3BridgeDependencies {
  readonly runPreVerifyPipeline: typeof M3.runPreVerifyPipeline;
  readonly orchestrateSigmas: typeof M3.orchestrateSigmas;
  readonly reconstructFileKey: typeof M3.reconstructFileKey;
  readonly combineAndDecrypt: typeof M3.combineAndDecrypt;
  readonly verifyRegistrySnapshots: typeof M3.verifyRegistrySnapshots;
  readonly verifyGateRecipientPubkeys: typeof M3.verifyGateRecipientPubkeys;
  readonly verifyPluginIntegrity: typeof M3.verifyPluginIntegrity;
  readonly assertCrossVendorTeeDisjoint: typeof M3.assertCrossVendorTeeDisjoint;
  readonly assertShredStateSignable: typeof M3.assertShredStateSignable;
  readonly verifySupersessionLineage: typeof M3.verifySupersessionLineage;
  readonly applyRuntimeHardening: typeof M3.applyRuntimeHardening;
  readonly dispatchProfile: typeof M3.dispatchProfile;
  readonly rejectMode3: typeof M3.rejectMode3;
  readonly assembleRevealArtifactBundle: typeof M3.assembleRevealArtifactBundle;
  readonly jcsCanonicalize: typeof M3.jcsCanonicalize;
  readonly jcsDigest: typeof M3.jcsDigest;
  readonly decryptAeadPayload: typeof M3.decryptAeadPayload;
}

export interface RunM3CombinerBridgeInput {
  readonly combinerInput: M3CombinerInput;
  readonly lowLevelArtifactInput?: Omit<M3LowLevelArtifactInput, "plaintext">;
}

export type RunM3CombinerBridgeResult =
  | {
      readonly ok: true;
      readonly plaintext: Uint8Array;
      readonly m3_artifact_digest: Hex32;
      readonly m3_scaffold?: M3LowLevelArtifactResult["bundle"];
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly subCodes: readonly string[];
      readonly metadata?: Readonly<Record<string, string | number | bigint | Hex32>>;
    };

export function createM3BridgeDependencies(
  overrides: Partial<M3BridgeDependencies> = {},
): M3BridgeDependencies {
  return {
    runPreVerifyPipeline: M3.runPreVerifyPipeline,
    orchestrateSigmas: M3.orchestrateSigmas,
    reconstructFileKey: M3.reconstructFileKey,
    combineAndDecrypt: M3.combineAndDecrypt,
    verifyRegistrySnapshots: M3.verifyRegistrySnapshots,
    verifyGateRecipientPubkeys: M3.verifyGateRecipientPubkeys,
    verifyPluginIntegrity: M3.verifyPluginIntegrity,
    assertCrossVendorTeeDisjoint: M3.assertCrossVendorTeeDisjoint,
    assertShredStateSignable: M3.assertShredStateSignable,
    verifySupersessionLineage: M3.verifySupersessionLineage,
    applyRuntimeHardening: M3.applyRuntimeHardening,
    dispatchProfile: M3.dispatchProfile,
    rejectMode3: M3.rejectMode3,
    assembleRevealArtifactBundle: M3.assembleRevealArtifactBundle,
    jcsCanonicalize: M3.jcsCanonicalize,
    jcsDigest: M3.jcsDigest,
    decryptAeadPayload: M3.decryptAeadPayload,
    ...overrides,
  };
}

export function assertM3BridgeExports(deps: M3BridgeDependencies): void {
  for (const name of REQUIRED_M3_COMBINER_EXPORTS) {
    if (typeof deps[name] !== "function") {
      throw new Error(`M3 combiner SDK export missing or non-function: ${name}`);
    }
  }
}

export function runM3CombinerBridge(
  input: RunM3CombinerBridgeInput,
  deps: M3BridgeDependencies = createM3BridgeDependencies(),
): RunM3CombinerBridgeResult {
  assertM3BridgeExports(deps);
  deps.applyRuntimeHardening();
  const result = deps.combineAndDecrypt(input.combinerInput);
  if (!result.ok) return result;

  if (input.lowLevelArtifactInput === undefined) {
    return {
      ok: true,
      plaintext: result.plaintext,
      m3_artifact_digest: result.artifactDigest,
    };
  }

  const scaffold = deps.assembleRevealArtifactBundle({
    ...input.lowLevelArtifactInput,
    plaintext: result.plaintext,
  });
  deps.jcsCanonicalize(scaffold.bundle as unknown as M3.JcsValue);
  const digest = deps.jcsDigest(scaffold.bundle as unknown as M3.JcsValue);
  if (digest !== scaffold.digest) {
    throw new Error("M3 scaffold drift: jcsDigest(bundle) does not equal returned digest.");
  }
  return {
    ok: true,
    plaintext: result.plaintext,
    m3_artifact_digest: scaffold.digest,
    m3_scaffold: scaffold.bundle,
  };
}
