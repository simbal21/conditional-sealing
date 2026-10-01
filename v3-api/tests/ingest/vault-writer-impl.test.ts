// T1.2 + F-WRAP-1 tests — RealVaultWriter (the real ingest seal → deal → WRAP →
// store → destroy path).
//
// Proves, with a fake sealer (known DEK) + a fake vault + a fake share store +
// per-commit gate keypairs (no live infra — pure unit test, runs in CI without
// Postgres/RPC):
//   1. NON-CUSTODY: what the writer persists to `dek_share_records` is ONLY
//      WRAPPED material (the §6.2 hybrid-wrap payload) — never a raw 32-byte
//      reconstructable share. The persisted wrapped payloads cannot be combined
//      into the DEK without the gate PRIVATE keys.
//   2. ROUND-TRIP: unwrapping each persisted stanza with ITS gate private key
//      recovers the original Shamir share, and `combineDek` reconstructs the EXACT
//      known DEK — so the wrap-to-gate flow is correct end-to-end.
//   3. CRYPTO-SHRED DISCIPLINE: after `write` returns, the assembled DEK and every
//      RAW in-memory share value are zeroized — the only key material that survives
//      is the WRAPPED, threshold-protected, persisted stanzas.
//   4. PLATFORM PRINCIPLE: the same writer drives two PDA-selected access-structure
//      profiles (FIXED_ONLY + RECIPIENT_K_OF_N) with no code change.
//   5. The DEK never reaches the vault (CealisV3Vault has no key parameter) and the
//      plaintext is never persisted in cleartext; the vault stores the age envelope.

import { describe, expect, it } from "vitest";
import {
  RealVaultWriter,
  createRealVaultWriter,
  type GateRecipientKeyProvider,
  type IngestContextResolver,
  type IngestWriteContext,
  type SealerPort,
  type SealOutput,
  type ShareRecordStore,
} from "../../src/ingest/vault-writer-impl.js";
import type { WrappedShareRecord, G3Choice } from "../../src/ingest/wrap-shares.js";
import { gateRecipientKey } from "../../src/ingest/wrap-shares.js";
import type { HCommitArtifacts } from "../../src/h-commit/construct.js";
import type { Hex32 } from "../../src/h-commit/index.js";
import type {
  CealisV3Vault,
  VaultBlob,
  VaultRef,
} from "../../src/vault/cealis-v3-vault.js";
import {
  combineDek,
  dealDek as realDeal,
  decodeAgeEnvelope,
  decodeWrappedStanzaPayload,
  generateHybridWrapRecipientKeypair,
  unwrapShareForRecipient,
  type AccessStructureProfile,
  type HybridWrapRecipientPrivateKeys,
  type ShareRecord,
} from "@cealis/v3-crypto";

const hex32 = (seed: string): Hex32 => `0x${seed.repeat(64).slice(0, 64)}`;

const H_COMMIT = hex32("ab");
const VAULT_REF = `vault://${H_COMMIT}`;
/** A known, fixed DEK so the round-trip can assert exact reconstruction. */
const KNOWN_DEK = (): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_unused, i) => (i * 7 + 3) & 0xff);
/** The inner AEAD payload (the writer wraps shares + envelopes this). */
const CIPHERTEXT = new TextEncoder().encode("opaque-aead-ciphertext-bytes");
const COMMIT_AAD_BYTES = Uint8Array.from({ length: 523 }, (_unused, i) => (i * 13 + 1) & 0xff);
const COMMIT_VERSION_ONWIRE = 0x0302;
const COMMIT_AAD_DIGEST = hex32("cd");
const PLUGIN_VERSION_DIGEST = Uint8Array.from({ length: 32 }, (_u, i) => (i + 1) & 0xff);
const CC_DIGEST_N = Uint8Array.from({ length: 32 }, (_u, i) => (i + 0x40) & 0xff);
const CC_DIGEST_0 = Uint8Array.from({ length: 32 }, (_u, i) => (i + 0x80) & 0xff);

/** GateKind numeric values (mirror M2 Enums.sol). */
const GATE_LIT = 0;
const GATE_DRAND = 2;
const GATE_G4 = 3;
const GATE_CONDITIONAL = 4;

/** commit_AAD shape the writer only reads `.g3_choice` off (1 = drand). */
const FAKE_COMMIT_AAD = { g3_choice: 1, plugin_version_digest: PLUGIN_VERSION_DIGEST } as unknown as HCommitArtifacts["commit_AAD"];

const FAKE_HCOMMIT = {
  authorizationId: hex32("01"),
  h_commit: H_COMMIT,
  aad_digest: hex32("02"),
  commit_context_digest: hex32("03"),
  commit_AAD: FAKE_COMMIT_AAD,
  commit_context: {},
} as unknown as HCommitArtifacts;

/** Fake sealer: returns the known DEK + a fixed inner AEAD ciphertext + binding +
 *  the per-payload digests the wrap path binds. */
function fakeSealer(): SealerPort {
  return {
    seal(): SealOutput {
      return {
        dek: KNOWN_DEK(),
        ciphertext: CIPHERTEXT,
        commit_context_digest_0: CC_DIGEST_0,
        commit_aad_bytes: COMMIT_AAD_BYTES,
        commit_version_onwire: COMMIT_VERSION_ONWIRE,
        commit_aad_digest: COMMIT_AAD_DIGEST,
        plugin_version_digest: PLUGIN_VERSION_DIGEST,
        commit_context_digest_N: CC_DIGEST_N,
      };
    },
  };
}

interface CapturedPut {
  readonly ref: VaultRef;
  readonly ciphertext: Uint8Array;
  readonly commit_aad_bytes: Uint8Array;
  readonly commit_version_onwire: number;
  readonly commit_aad_digest: string;
  readonly retention_policy_id: string;
  readonly retention_expires_at: string;
  readonly payload_classification: Record<string, unknown>;
}

function fakeVault(): { vault: CealisV3Vault; puts: CapturedPut[] } {
  const puts: CapturedPut[] = [];
  const vault: CealisV3Vault = {
    async putBlob(input) {
      puts.push({
        ref: input.ref,
        ciphertext: input.ciphertext,
        commit_aad_bytes: input.commitBinding.commit_aad_bytes,
        commit_version_onwire: input.commitBinding.commit_version_onwire,
        commit_aad_digest: input.commitBinding.commit_aad_digest,
        retention_policy_id: input.meta.retention_policy_id,
        retention_expires_at: input.meta.retention_expires_at,
        payload_classification: input.meta.payload_classification,
      });
      return { ref: input.ref, byte_len: input.ciphertext.byteLength };
    },
    async getBlob(): Promise<VaultBlob> {
      throw new Error("not used in this test");
    },
    async deleteBlob(input) {
      return { ref: input.ref, shredded_at: "1970-01-01T00:00:00.000Z" };
    },
    async getRetentionStatus(): Promise<never> {
      throw new Error("not used in this test");
    },
    async listExpired(): Promise<readonly VaultRef[]> {
      return [];
    },
  };
  return { vault, puts };
}

function fakeShareStore(): { store: ShareRecordStore; persisted: WrappedShareRecord[][] } {
  const persisted: WrappedShareRecord[][] = [];
  const store: ShareRecordStore = {
    async persist(input) {
      persisted.push([...input.records]);
    },
  };
  return { store, persisted };
}

/** Per-commit gate keypair store the test uses both to provide pubkeys (wrap) and
 *  to hold privkeys (unwrap, to prove the round-trip). */
function gateKeys(profile: AccessStructureProfile): {
  provider: GateRecipientKeyProvider;
  privByKey: Map<string, HybridWrapRecipientPrivateKeys>;
} {
  const privByKey = new Map<string, HybridWrapRecipientPrivateKeys>();
  const slots: { gateKind: number; cr: number }[] = [
    { gateKind: GATE_LIT, cr: 0 },
    { gateKind: GATE_DRAND, cr: 0 },
    { gateKind: GATE_G4, cr: 0 },
  ];
  if (profile.kind === "RECIPIENT_1_OF_1") slots.push({ gateKind: GATE_CONDITIONAL, cr: 0 });
  if (profile.kind === "RECIPIENT_K_OF_N") {
    for (let i = 0; i < profile.n_conditional; i++) slots.push({ gateKind: GATE_CONDITIONAL, cr: i });
  }
  for (const s of slots) {
    privByKey.set(gateRecipientKey(s.gateKind, s.cr), generateHybridWrapRecipientKeypair());
  }
  const provider: GateRecipientKeyProvider = {
    resolve: () => {
      const map = new Map<string, { pk_x25519: Uint8Array; pk_mlkem: Uint8Array }>();
      for (const [key, priv] of privByKey) {
        map.set(key, { pk_x25519: priv.pk_x25519, pk_mlkem: priv.pk_mlkem });
      }
      return map;
    },
  };
  return { provider, privByKey };
}

function staticResolver(profile: AccessStructureProfile): IngestContextResolver {
  const context: IngestWriteContext = {
    hCommit: FAKE_HCOMMIT,
    accessStructureProfile: profile,
    retentionPolicyId: "obligation_plus_3y",
    retentionExpiresAt: "2030-01-01T00:00:00.000Z",
    shredAuthority: "subject",
    vaultRef: VAULT_REF,
  };
  return { resolve: () => context };
}

function capturingDealer(): { dealDekFn: typeof realDeal; captured: ShareRecord[][] } {
  const captured: ShareRecord[][] = [];
  const dealDekFn: typeof realDeal = (dek, profile, options) => {
    const records = realDeal(dek, profile, options);
    captured.push(records);
    return records;
  };
  return { dealDekFn, captured };
}

const G3: G3Choice = "drand";

/** Unwrap each persisted wrapped stanza with its gate private key → ShareRecord. */
function unwrapAll(
  records: readonly WrappedShareRecord[],
  privByKey: Map<string, HybridWrapRecipientPrivateKeys>,
): ShareRecord[] {
  return records.map((r) => {
    const recipient = privByKey.get(gateRecipientKey(r.gate_kind, r.conditional_recipient_index));
    if (recipient === undefined) throw new Error(`no privkey for ${r.gate_kind}:${r.conditional_recipient_index}`);
    const wrapped = decodeWrappedStanzaPayload(r.wrapped_payload);
    const result = unwrapShareForRecipient({
      stanza_index: r.stanza_index,
      binding_tag: r.binding_tag,
      plugin_version_digest: r.plugin_version_digest,
      commit_context_digest_N: r.commit_context_digest_N,
      share_domain: r.share_domain as never,
      share_role: r.share_role as never,
      logical_index: r.logical_index,
      x: r.x,
      recipient,
      wrapped,
    });
    if (!result.ok) throw new Error(`unwrap failed: ${result.error}`);
    return {
      share_domain: r.share_domain as ShareRecord["share_domain"],
      share_role: r.share_role as ShareRecord["share_role"],
      logical_index: r.logical_index,
      x: r.x,
      value: result.share,
    };
  });
}

describe("RealVaultWriter — seal → deal → WRAP → store → destroy", () => {
  it("NON-CUSTODY: persists ONLY WRAPPED stanzas; the raw DEK never reaches the vault or share store", async () => {
    const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
    const { vault, puts } = fakeVault();
    const { store, persisted } = fakeShareStore();
    const { provider } = gateKeys(profile);

    const writer = new RealVaultWriter({
      sealer: fakeSealer(),
      vault,
      shareStore: store,
      resolveContext: staticResolver(profile),
      gateRecipientKeys: provider,
    });

    const result = await writer.write({
      h_commit: H_COMMIT,
      plaintext: new TextEncoder().encode("alice-kyc-plaintext"),
      payload_classification: { pii_class: "kyc" },
    });
    expect(result.vault_ref).toBe(VAULT_REF);

    // The vault stores the AGE ENVELOPE (wrapped stanzas + payload), not a raw share.
    expect(puts).toHaveLength(1);
    const put = puts[0]!;
    const decoded = decodeAgeEnvelope(put.ciphertext);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.stanzas).toHaveLength(3);
    expect(new TextDecoder().decode(put.ciphertext)).not.toContain("alice-kyc-plaintext");

    // dek_share_records holds ONLY wrapped payloads — never a raw 32-byte share.
    expect(persisted).toHaveLength(1);
    const batch = persisted[0]!;
    expect(batch).toHaveLength(3); // Lit, G3, G4
    for (const r of batch) {
      // 1168 = 32 (pk_eph) + 1088 (ct_mlkem) + 48 (wrapped_share AEAD). Far from 39.
      expect(r.wrapped_payload.byteLength).toBe(1168);
      // No property on the wrapped record carries a raw 32-byte share value.
      expect(Object.prototype.hasOwnProperty.call(r, "value")).toBe(false);
    }
  });

  it("ROUND-TRIP: unwrapping the persisted stanzas reconstructs the EXACT known DEK", async () => {
    const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
    const { vault } = fakeVault();
    const { store, persisted } = fakeShareStore();
    const { provider, privByKey } = gateKeys(profile);

    const writer = new RealVaultWriter({
      sealer: fakeSealer(),
      vault,
      shareStore: store,
      resolveContext: staticResolver(profile),
      gateRecipientKeys: provider,
    });
    await writer.write({
      h_commit: H_COMMIT,
      plaintext: new TextEncoder().encode("alice-kyc-plaintext"),
      payload_classification: { pii_class: "kyc" },
    });

    // Unwrap with the gate private keys → shares → combine → the known DEK.
    const shares = unwrapAll(persisted[0]!, privByKey);
    const combine = combineDek(shares, profile);
    expect(combine.ok).toBe(true);
    if (combine.ok) expect(Buffer.from(combine.dek)).toEqual(Buffer.from(KNOWN_DEK()));
  });

  it("NON-CUSTODY: the persisted wrapped stanzas WITHOUT the gate private keys cannot reconstruct the DEK", async () => {
    const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
    const { vault } = fakeVault();
    const { store, persisted } = fakeShareStore();
    const { provider } = gateKeys(profile);

    const writer = createRealVaultWriter({
      sealer: fakeSealer(),
      vault,
      shareStore: store,
      resolveContext: staticResolver(profile),
      gateRecipientKeys: provider,
    });
    await writer.write({
      h_commit: H_COMMIT,
      plaintext: new TextEncoder().encode("alice-kyc-plaintext"),
      payload_classification: {},
    });

    // An adversary holding the FULL persisted state (the wrapped stanzas) but NO
    // gate private key cannot get any share back: decoding the wrapped payload as
    // if it were a 32-byte share is structurally impossible (1168 != 32), and
    // unwrapping with a WRONG (freshly-minted) private key fails the AEAD.
    const batch = persisted[0]!;
    const wrongKey = generateHybridWrapRecipientKeypair();
    for (const r of batch) {
      const wrapped = decodeWrappedStanzaPayload(r.wrapped_payload);
      const result = unwrapShareForRecipient({
        stanza_index: r.stanza_index,
        binding_tag: r.binding_tag,
        plugin_version_digest: r.plugin_version_digest,
        commit_context_digest_N: r.commit_context_digest_N,
        share_domain: r.share_domain as never,
        share_role: r.share_role as never,
        logical_index: r.logical_index,
        x: r.x,
        recipient: wrongKey,
        wrapped,
      });
      expect(result.ok).toBe(false);
    }
  });

  it("CRYPTO-SHRED: the assembled DEK and every in-memory RAW share value are zeroized after write", async () => {
    const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
    const { vault } = fakeVault();
    const { store } = fakeShareStore();
    const { provider } = gateKeys(profile);
    const { dealDekFn, captured } = capturingDealer();

    let dekRef: Uint8Array | undefined;
    const sealer: SealerPort = {
      seal() {
        dekRef = KNOWN_DEK();
        return {
          dek: dekRef,
          ciphertext: CIPHERTEXT,
          commit_context_digest_0: CC_DIGEST_0,
          commit_aad_bytes: COMMIT_AAD_BYTES,
          commit_version_onwire: COMMIT_VERSION_ONWIRE,
          commit_aad_digest: COMMIT_AAD_DIGEST,
          plugin_version_digest: PLUGIN_VERSION_DIGEST,
          commit_context_digest_N: CC_DIGEST_N,
        };
      },
    };

    const writer = new RealVaultWriter({
      sealer,
      vault,
      shareStore: store,
      resolveContext: staticResolver(profile),
      gateRecipientKeys: provider,
      dealDekFn,
    });
    await writer.write({
      h_commit: H_COMMIT,
      plaintext: new TextEncoder().encode("bob-kyc-plaintext"),
      payload_classification: { pii_class: "kyc" },
    });

    expect(dekRef).toBeDefined();
    expect(dekRef!.every((b) => b === 0)).toBe(true);
    expect(captured).toHaveLength(1);
    for (const record of captured[0]!) {
      expect(record.value.every((b) => b === 0)).toBe(true);
    }
  });

  it("CRYPTO-SHRED: the DEK is still zeroized when the share store throws (finally runs)", async () => {
    const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
    const { vault } = fakeVault();
    const { provider } = gateKeys(profile);
    const { dealDekFn, captured } = capturingDealer();

    let dekRef: Uint8Array | undefined;
    const sealer: SealerPort = {
      seal() {
        dekRef = KNOWN_DEK();
        return {
          dek: dekRef,
          ciphertext: CIPHERTEXT,
          commit_context_digest_0: CC_DIGEST_0,
          commit_aad_bytes: COMMIT_AAD_BYTES,
          commit_version_onwire: COMMIT_VERSION_ONWIRE,
          commit_aad_digest: COMMIT_AAD_DIGEST,
          plugin_version_digest: PLUGIN_VERSION_DIGEST,
          commit_context_digest_N: CC_DIGEST_N,
        };
      },
    };
    const throwingStore: ShareRecordStore = {
      async persist() {
        throw new Error("dek_share_records insert failed");
      },
    };

    const writer = new RealVaultWriter({
      sealer,
      vault,
      shareStore: throwingStore,
      resolveContext: staticResolver(profile),
      gateRecipientKeys: provider,
      dealDekFn,
    });

    await expect(
      writer.write({
        h_commit: H_COMMIT,
        plaintext: new Uint8Array([1, 2, 3]),
        payload_classification: {},
      }),
    ).rejects.toThrow("dek_share_records insert failed");

    expect(dekRef!.every((b) => b === 0)).toBe(true);
    expect(captured).toHaveLength(1);
    for (const record of captured[0]!) {
      expect(record.value.every((b) => b === 0)).toBe(true);
    }
  });

  it("PLATFORM PRINCIPLE: the same writer drives RECIPIENT_K_OF_N purely from the PDA-resolved profile", async () => {
    const profile: AccessStructureProfile = {
      kind: "RECIPIENT_K_OF_N",
      n_conditional: 3,
      k_conditional: 2,
    };
    const { vault } = fakeVault();
    const { store, persisted } = fakeShareStore();
    const { provider, privByKey } = gateKeys(profile);

    const writer = createRealVaultWriter({
      sealer: fakeSealer(),
      vault,
      shareStore: store,
      resolveContext: staticResolver(profile),
      gateRecipientKeys: provider,
    });
    await writer.write({
      h_commit: H_COMMIT,
      plaintext: new TextEncoder().encode("carol-kyc-plaintext"),
      payload_classification: { pii_class: "kyc" },
    });

    const batch = persisted[0]!;
    // 3 fixed top-level stanzas (Lit, G3, G4) + n_conditional (3) branch stanzas.
    expect(batch).toHaveLength(3 + 3);
    for (const r of batch) expect(r.wrapped_payload.byteLength).toBe(1168);

    // Unwrap all, then combine with the 3 fixed top shares + a k_conditional (2)
    // subset of the branch shares → reconstructs the known DEK (PDA-driven).
    const shares = unwrapAll(batch, privByKey);
    const top = shares.filter((s) => s.share_domain === 1);
    const branch = shares.filter((s) => s.share_domain === 2);
    expect(top).toHaveLength(3);
    expect(branch).toHaveLength(3);
    const combine = combineDek([...top, ...branch.slice(0, 2)], profile);
    expect(combine.ok).toBe(true);
    if (combine.ok) expect(Buffer.from(combine.dek)).toEqual(Buffer.from(KNOWN_DEK()));
  });
});

void G3;
