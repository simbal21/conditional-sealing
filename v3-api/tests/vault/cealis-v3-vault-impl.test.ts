// CealisV3VaultImpl contract tests via the real FilesystemVaultStore backend.
//
// These run ALWAYS (no Postgres needed) and exercise the full CealisV3Vault
// producer-seam contract against a REAL on-disk store (Rule 12 — not an
// in-memory shortcut): store/retrieve round-trip, AAD-binding-mismatch rejected
// (VAULT_REF_COLLISION), crypto-shred deletes + is irreversible, the
// no-PII/no-plaintext invariant (ciphertext bytes only, no key/DEK columns ever
// touched), disabled-authority refusal, idempotent re-put, and retention listing.
//
// A real Postgres-bytea variant of these same assertions (append-only audit-log
// shred row) lives in `postgres-vault-store.test.ts` (V3_TEST_PG_URL-gated).

import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CealisV3VaultImpl,
  FilesystemVaultStore,
  VaultError,
  type CealisV3Vault,
  type VaultCommitBinding,
} from "../../src/vault/index.js";

const PLAINTEXT_TOKEN = "SECRET-PII-Erika-Mustermann-1990-01-01";
const DEK_TOKEN = "DEK-0xdeadbeefcafef00d";

/** AEAD ciphertext stand-in: deterministic opaque bytes that DELIBERATELY do not
 *  contain the plaintext or the DEK token (the vault must store ciphertext only;
 *  this asserts it never receives, stores, or returns either secret). */
function fakeCiphertext(seed: string): Uint8Array {
  return new TextEncoder().encode(`AEAD::${seed}::opaque-ciphertext-no-secrets`);
}

function binding(commitVersion = 0x0301, digest = "0xabc123"): VaultCommitBinding {
  return {
    commit_aad_bytes: new TextEncoder().encode(`commit-aad::${commitVersion}::${digest}`),
    commit_version_onwire: commitVersion,
    commit_aad_digest: digest,
  };
}

function meta(retentionExpiresAt = "2029-01-01T00:00:00.000Z") {
  return {
    payload_classification: { kind: "kyc", fields: ["name", "dob"] },
    retention_policy_id: "obligation_plus_3y",
    retention_expires_at: retentionExpiresAt,
  };
}

describe("CealisV3VaultImpl (FilesystemVaultStore backend)", () => {
  let dir: string;
  let vault: CealisV3Vault;
  let fixedNow: Date;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cealis-vault-test-"));
    fixedNow = new Date("2026-06-02T12:00:00.000Z");
    vault = new CealisV3VaultImpl({
      store: new FilesystemVaultStore({ rootDir: dir }),
      now: () => fixedNow,
    });
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("stores and retrieves a ciphertext blob with its inseparable binding (round-trip)", async () => {
    const ref = "vault://0xh_commit_round_trip";
    const ct = fakeCiphertext("rt");
    const b = binding();

    const put = await vault.putBlob({ ref, ciphertext: ct, commitBinding: b, meta: meta() });
    expect(put.ref).toBe(ref);
    expect(put.byte_len).toBe(ct.byteLength);

    const got = await vault.getBlob(ref);
    expect(Array.from(got.ciphertext)).toEqual(Array.from(ct));
    // C1: binding returned inseparably with the ciphertext, byte-exact.
    expect(Array.from(got.commitBinding.commit_aad_bytes)).toEqual(Array.from(b.commit_aad_bytes));
    expect(got.commitBinding.commit_version_onwire).toBe(b.commit_version_onwire);
    expect(got.commitBinding.commit_aad_digest).toBe(b.commit_aad_digest);
    // Metadata computed by the vault layer.
    expect(got.meta.byte_len).toBe(ct.byteLength);
    expect(got.meta.created_at).toBe(fixedNow.toISOString());
    expect(got.meta.retention_expires_at).toBe("2029-01-01T00:00:00.000Z");
  });

  it("is idempotent on identical re-put (same ref + same bytes = no-op, no collision)", async () => {
    const ref = "vault://0xh_commit_idem";
    const ct = fakeCiphertext("idem");
    const b = binding();
    await vault.putBlob({ ref, ciphertext: ct, commitBinding: b, meta: meta() });
    // Re-put identical bytes must NOT throw and must report the same byte_len.
    const second = await vault.putBlob({ ref, ciphertext: ct, commitBinding: b, meta: meta() });
    expect(second.byte_len).toBe(ct.byteLength);
  });

  it("rejects a same-ref put with different ciphertext bytes (VAULT_REF_COLLISION)", async () => {
    const ref = "vault://0xh_commit_collide";
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("v1"), commitBinding: binding(), meta: meta() });
    await expect(
      vault.putBlob({ ref, ciphertext: fakeCiphertext("v2-different"), commitBinding: binding(), meta: meta() }),
    ).rejects.toMatchObject({
      name: "VaultError",
      context: { reasonCode: "VAULT_REF_COLLISION", operation: "putBlob" },
    });
  });

  it("rejects a same-ref put with a DIFFERENT commit binding (AAD-binding mismatch → collision)", async () => {
    const ref = "vault://0xh_commit_aad_mismatch";
    const ct = fakeCiphertext("aad");
    // Same ciphertext, but a DIFFERENT commit_aad binding — must be rejected as a
    // collision (a blob's binding is inseparable and immutable; you cannot rebind).
    await vault.putBlob({ ref, ciphertext: ct, commitBinding: binding(0x0301, "0xaaa"), meta: meta() });
    await expect(
      vault.putBlob({ ref, ciphertext: ct, commitBinding: binding(0x0303, "0xbbb"), meta: meta() }),
    ).rejects.toMatchObject({
      name: "VaultError",
      context: { reasonCode: "VAULT_REF_COLLISION" },
    });
  });

  it("refuses to store a blob with a missing/empty commit binding (defends C1)", async () => {
    const ref = "vault://0xh_commit_no_binding";
    await expect(
      vault.putBlob({
        ref,
        ciphertext: fakeCiphertext("nb"),
        commitBinding: {
          commit_aad_bytes: new Uint8Array(0),
          commit_version_onwire: 0x0301,
          commit_aad_digest: "0xabc",
        },
        meta: meta(),
      }),
    ).rejects.toMatchObject({
      name: "VaultError",
      context: { reasonCode: "VAULT_COMMIT_BINDING_MISSING", commitAADRoundTripStatus: "malformed" },
    });
  });

  it("getBlob on an unknown ref throws VAULT_REF_NOT_FOUND", async () => {
    await expect(vault.getBlob("vault://0xnope")).rejects.toMatchObject({
      name: "VaultError",
      context: { reasonCode: "VAULT_REF_NOT_FOUND", operation: "getBlob" },
    });
  });

  it("crypto-shred deletes the blob and is IRREVERSIBLE (subsequent getBlob fails)", async () => {
    const ref = "vault://0xh_commit_shred";
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("shred"), commitBinding: binding(), meta: meta() });
    // present before shred
    await expect(vault.getBlob(ref)).resolves.toBeDefined();

    const shred = await vault.deleteBlob({ ref, shredAuthority: "subject" });
    expect(shred.ref).toBe(ref);
    expect(shred.shredded_at).toBe(fixedNow.toISOString());

    // Irreversible: the ciphertext is gone, no reconstruction path.
    await expect(vault.getBlob(ref)).rejects.toMatchObject({
      context: { reasonCode: "VAULT_REF_NOT_FOUND" },
    });
    // Re-shred of an already-gone ref → NOT_FOUND (no silent fake-success, Rule 19).
    await expect(vault.deleteBlob({ ref, shredAuthority: "subject" })).rejects.toMatchObject({
      context: { reasonCode: "VAULT_REF_NOT_FOUND" },
    });
  });

  it("appends an append-only shred-audit row carrying NO PII", async () => {
    const ref = "vault://0xh_commit_audit";
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("audit"), commitBinding: binding(), meta: meta() });
    await vault.deleteBlob({ ref, shredAuthority: "operator" });

    const auditRaw = await readFile(join(dir, "shred-audit.jsonl"), "utf-8");
    const lines = auditRaw.trim().split("\n").filter(Boolean);
    expect(lines.length).toBe(1);
    const row = JSON.parse(lines[0]!);
    expect(row).toMatchObject({ action: "vault_shred", vault_ref: ref, shred_authority: "operator" });
    // No PII / no plaintext / no DEK ever lands in the audit row.
    expect(auditRaw).not.toContain(PLAINTEXT_TOKEN);
    expect(auditRaw).not.toContain(DEK_TOKEN);
  });

  it("refuses crypto-shred when PDA shred authority is 'disabled' (feature, not bug)", async () => {
    const ref = "vault://0xh_commit_disabled";
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("dis"), commitBinding: binding(), meta: meta() });
    await expect(vault.deleteBlob({ ref, shredAuthority: "disabled" })).rejects.toMatchObject({
      name: "VaultError",
      context: { reasonCode: "VAULT_SHRED_AUTHORITY_DISABLED", shredAuthority: "disabled" },
    });
    // The blob must still be retrievable — disabled means erasure is OFF.
    await expect(vault.getBlob(ref)).resolves.toBeDefined();
  });

  it("NO-PII / NO-PLAINTEXT / NO-DEK invariant — nothing secret is ever written to disk", async () => {
    const ref = "vault://0xh_commit_no_pii";
    // The vault is handed ONLY opaque ciphertext (no plaintext/DEK is even
    // representable in putBlob's signature). Assert at the disk layer that the
    // secrets never appear in any persisted byte.
    await vault.putBlob({
      ref,
      ciphertext: fakeCiphertext("nopii"),
      commitBinding: binding(),
      meta: meta(),
    });

    const files = await readdir(dir);
    for (const f of files) {
      const raw = await readFile(join(dir, f));
      const text = raw.toString("binary");
      expect(text).not.toContain(PLAINTEXT_TOKEN);
      expect(text).not.toContain(DEK_TOKEN);
    }
  });

  it("getRetentionStatus surfaces the stored retention floor (D3 / §195 BGB)", async () => {
    const ref = "vault://0xh_commit_retention";
    await vault.putBlob({
      ref,
      ciphertext: fakeCiphertext("ret"),
      commitBinding: binding(),
      meta: meta("2030-07-01T00:00:00.000Z"),
    });
    const status = await vault.getRetentionStatus(ref);
    expect(status.h_commit).toBe(ref);
    expect(status.retention_expires_at).toBe("2030-07-01T00:00:00.000Z");
    expect(status.retention_policy_id).toBe("obligation_plus_3y");
    // Retention-floor framing for the worker (no PII).
    expect(status.vault_access_log_retention).toBe("P12M");
    expect(status.webhook_metadata_retention).toBe("P90D");
  });

  it("listExpired returns only refs past their retention floor (retention worker surface)", async () => {
    await vault.putBlob({
      ref: "vault://0xexpired",
      ciphertext: fakeCiphertext("exp"),
      commitBinding: binding(),
      meta: meta("2025-01-01T00:00:00.000Z"),
    });
    await vault.putBlob({
      ref: "vault://0xlive",
      ciphertext: fakeCiphertext("live"),
      commitBinding: binding(),
      meta: meta("2099-01-01T00:00:00.000Z"),
    });
    const expired = await vault.listExpired("2026-06-02T12:00:00.000Z");
    expect(expired).toContain("vault://0xexpired");
    expect(expired).not.toContain("vault://0xlive");
  });

  it("is backend-agnostic — same contract holds, no hardcoded backend (PLATFORM PRINCIPLE)", async () => {
    // The impl never names a backend; it talks only to VaultStore. Swapping the
    // store (here, a second Filesystem store at a different root) is transparent.
    const dir2 = await mkdtemp(join(tmpdir(), "cealis-vault-test2-"));
    try {
      const v2 = new CealisV3VaultImpl({ store: new FilesystemVaultStore({ rootDir: dir2 }) });
      const ref = "vault://0xagnostic";
      const ct = fakeCiphertext("agnostic");
      await v2.putBlob({ ref, ciphertext: ct, commitBinding: binding(), meta: meta() });
      const got = await v2.getBlob(ref);
      expect(Array.from(got.ciphertext)).toEqual(Array.from(ct));
    } finally {
      await rm(dir2, { recursive: true, force: true });
    }
  });

  it("surfaces VaultError as a real Error subclass with a Rule-47 context bag", async () => {
    try {
      await vault.getBlob("vault://0xmissing-context-check");
      throw new Error("expected VaultError");
    } catch (e) {
      expect(e).toBeInstanceOf(VaultError);
      const err = e as VaultError;
      expect(err).toBeInstanceOf(Error);
      expect(err.context.vaultBackendId).toBe("filesystem");
      expect(err.context.operation).toBe("getBlob");
      expect(err.context.reasonCode).toBe("VAULT_REF_NOT_FOUND");
    }
  });
});
