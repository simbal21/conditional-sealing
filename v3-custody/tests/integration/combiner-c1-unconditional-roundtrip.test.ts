// GATE-3 (C1) closure tests — the UNCONDITIONAL commit_AAD round-trip in
// `runPreVerifyPipeline`. Closes worker-3 R2b brief acceptance criteria:
//
//   (a) NO conditional survives around the round-trip call site (verified by
//       inspection + by tests below: historical 0x0301 payloads which were
//       previously SKIPPED now run the check and still succeed in the
//       untampered case via the bytes-equal-ignoring-version-window
//       semantic).
//   (b) The check binds against the on-wire bytes (R2a `VaultBlob
//       .commitBinding.commit_aad_bytes`) and gates on the on-wire version
//       (`profileDispatch.commitVersion`, NOT the post-decode/patched value
//       produced by `profile-dispatch.ts decodeActiveCompatibleCommitAAD`).
//   (c) Tampered commit_AAD with active version FAILS the check — the C1
//       attack the brief names, was previously bypassed only for historical
//       (where the version-guard skipped the check). Tests #3-#5 exercise
//       the active-version + post-dispatch substitution surface.
//   (d) Malformed/missing binding bytes fail-closed with a typed error
//       (`ERR_COMMIT_AAD_BINDING_MISSING`) — GATE-4 named sub-reader rule.
//
// These tests call `runPreVerifyPipeline` DIRECTLY (not via
// `combineAndDecrypt`) so they can craft the exact post-dispatch
// substitution patterns that the seam-level invariants catch. In normal
// operation the caller (worker-1 reveal coordinator) passes `VaultBlob
// .commitBinding.commit_aad_bytes` through the bridge, and the
// inseparability of that seam makes most of these mismatch cases
// type-unrepresentable upstream; this file tests the LAST-LINE refusal at
// the combiner boundary.

import { describe, expect, it } from "vitest";
import { COMMIT_AAD_BYTES } from "@cealis/v3-crypto";
import { dispatchProfile, runPreVerifyPipeline } from "../../src/combiner/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../../src/errors.js";
import { makeFixture } from "./combiner-testkit.js";

function attemptPreVerify(input: Parameters<typeof runPreVerifyPipeline>[0]): {
  ok: true;
} | { ok: false; code: string; subCodes: readonly string[] } {
  try {
    runPreVerifyPipeline(input);
    return { ok: true };
  } catch (error) {
    if (error instanceof CustodyError) {
      return { ok: false, code: error.code, subCodes: error.subCodes };
    }
    throw error;
  }
}

function preVerifyFromFixture(
  base: ReturnType<typeof makeFixture>,
  overrides: {
    readonly commitAADBytes?: Uint8Array;
    readonly dispatchBytes?: Uint8Array;
  } = {},
): { ok: true } | { ok: false; code: string; subCodes: readonly string[] } {
  const dispatchBytes = overrides.dispatchBytes ?? base.commitAAD;
  const profileDispatch = dispatchProfile({
    commitAAD: dispatchBytes,
    sigmas: base.sigmas,
  });
  return attemptPreVerify({
    authorizationId: base.authorizationId,
    hCommit: base.hCommit,
    authorizationBlock: base.authorizationBlock,
    blockHash: base.blockHash,
    commitAADBytes: overrides.commitAADBytes ?? base.commitAAD,
    ageEnvelope: base.ageEnvelope,
    sigmas: base.sigmas,
    profileDispatch,
    registrySnapshots: base.registrySnapshots,
    canonicalAddressPin: base.canonicalAddressPin,
  });
}

describe("combiner C1 unconditional commit_AAD round-trip", () => {
  it("ACTIVE-version untampered payload passes the unconditional round-trip", () => {
    // Sanity. The check ran for active before; it MUST keep running and pass
    // for an unmodified active payload.
    const base = makeFixture();
    expect(preVerifyFromFixture(base)).toEqual({ ok: true });
  });

  it("HISTORICAL 0x0301 untampered payload now runs the round-trip and passes via the version-window-skip semantic", () => {
    // Previously SKIPPED by the `if (commitVersion >= decoded.commit_version)`
    // guard (historical: on-wire 0x0301 < patched-decoded 0x0302 ⇒ skip). Now
    // it MUST RUN: the encoder writes 0x0302 at the version window, the
    // on-wire bytes carry 0x0301 there; bytesEqualIgnoringVersionWindow
    // skips those 2 positions and the rest byte-matches by codec
    // identity. So the unconditional check succeeds without breaking
    // historical compat.
    const base = makeFixture();
    const historical = new Uint8Array(base.commitAAD);
    historical[128] = 0x01;
    historical[129] = 0x03;
    expect(preVerifyFromFixture(base, { commitAADBytes: historical, dispatchBytes: historical })).toEqual({ ok: true });
  });

  it("post-dispatch ACTIVE-version substitution where the version window doesn't match the dispatched on-wire version FAILS the check (C1 attack — previously bypassed)", () => {
    // This is the C1 attack class: caller dispatches one set of bytes,
    // hands a DIFFERENT (lower-version) set of bytes to the pipeline. The
    // dispatch's `profileDispatch.commitVersion` is 0x0302 but the bytes
    // the pipeline now sees carry 0x0301 in their version window.
    // The version-window-equals-on-wire-version invariant catches this at
    // byte level — `ERR_COMMIT_AAD_VERSION_WINDOW_MISMATCH`.
    const base = makeFixture();
    const tampered = new Uint8Array(base.commitAAD);
    tampered[128] = 0x01;
    tampered[129] = 0x03;
    const result = preVerifyFromFixture(base, { commitAADBytes: tampered });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_COMMIT_AAD_VERSION_WINDOW_MISMATCH");
    }
  });

  it("post-dispatch tampering OUTSIDE the version window FAILS the check (active version, byte-level forgery)", () => {
    // Active-version payload, byte-level tampering at a NON-version
    // position. Dispatch ran on the legitimate bytes; the pipeline is
    // handed bytes that differ at offset 0 (the first authorizationId
    // byte). The round-trip's bytesEqualIgnoringVersionWindow detects
    // the mismatch and refuses — `ERR_AAD_DIGEST_MISMATCH`.
    const base = makeFixture();
    const tampered = new Uint8Array(base.commitAAD);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    const result = preVerifyFromFixture(base, { commitAADBytes: tampered });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_AAD_DIGEST_MISMATCH");
    }
  });

  it("malformed binding bytes (wrong length) fail-closed with ERR_COMMIT_AAD_BINDING_MISSING (GATE-4 sub-reader)", () => {
    // GATE-4 fail-closed sub-reader: the binding bytes input to the round-trip
    // MUST be exactly COMMIT_AAD_BYTES long. A truncated/padded buffer is a
    // missing-or-malformed binding and refuses with a typed sub-code, never
    // a silent default-pass.
    const base = makeFixture();
    const profileDispatch = dispatchProfile({
      commitAAD: base.commitAAD,
      sigmas: base.sigmas,
    });
    const truncated = base.commitAAD.slice(0, COMMIT_AAD_BYTES - 1);
    const result = attemptPreVerify({
      authorizationId: base.authorizationId,
      hCommit: base.hCommit,
      authorizationBlock: base.authorizationBlock,
      blockHash: base.blockHash,
      commitAADBytes: truncated,
      ageEnvelope: base.ageEnvelope,
      sigmas: base.sigmas,
      profileDispatch,
      registrySnapshots: base.registrySnapshots,
      canonicalAddressPin: base.canonicalAddressPin,
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_COMMIT_AAD_BINDING_MISSING");
    }
  });

  it("ACTIVE-version: empty buffer fails-closed with ERR_COMMIT_AAD_BINDING_MISSING (GATE-4 — zero-length input)", () => {
    // A zero-length Uint8Array would otherwise be silently treated as "no
    // binding" in a permissive implementation — GATE-4 requires a typed
    // throw. dispatchProfile would also reject this (too short to read
    // commit_version), but the round-trip's sub-reader assertion is the
    // defense-in-depth layer at the pre-verify boundary.
    const base = makeFixture();
    const profileDispatch = dispatchProfile({
      commitAAD: base.commitAAD,
      sigmas: base.sigmas,
    });
    const empty = new Uint8Array(0);
    const result = attemptPreVerify({
      authorizationId: base.authorizationId,
      hCommit: base.hCommit,
      authorizationBlock: base.authorizationBlock,
      blockHash: base.blockHash,
      commitAADBytes: empty,
      ageEnvelope: base.ageEnvelope,
      sigmas: base.sigmas,
      profileDispatch,
      registrySnapshots: base.registrySnapshots,
      canonicalAddressPin: base.canonicalAddressPin,
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_COMMIT_AAD_BINDING_MISSING");
    }
  });

  it("the round-trip is reachable for HISTORICAL on-wire payloads (proves the previous skip-on-historical guard is dead)", () => {
    // Behavioral proof of "unconditional": tamper a non-version byte on a
    // historical-0x0301 payload and confirm the round-trip throws. Under
    // the old code path this exact payload would have SKIPPED the check
    // and proceeded — combiner would have downgraded to FIXED_ONLY and
    // continued. Under the new unconditional code the check throws.
    const base = makeFixture();
    // First, build a clean historical on-wire payload + dispatch from it.
    const historical = new Uint8Array(base.commitAAD);
    historical[128] = 0x01;
    historical[129] = 0x03;
    // Now tamper a non-version byte AT the pipeline input ONLY (dispatch
    // continues to see the un-tampered historical bytes). The new
    // unconditional round-trip MUST catch this — under the old conditional
    // it was skipped entirely for historical.
    const tamperedAtPipeline = new Uint8Array(historical);
    tamperedAtPipeline[100] = (tamperedAtPipeline[100] ?? 0) ^ 0xff;
    const result = preVerifyFromFixture(base, {
      dispatchBytes: historical,
      commitAADBytes: tamperedAtPipeline,
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      // sub-code: either AAD_DIGEST_MISMATCH (non-version-window byte
      // tampered) — proves the check ran on a historical payload.
      expect(result.subCodes).toContain("ERR_AAD_DIGEST_MISMATCH");
    }
  });
});

