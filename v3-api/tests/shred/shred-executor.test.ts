// ShredExecutor cascade tests — T4.2 (Phase 3 Wave 4).
//
// Proves the real crypto-shred cascade (GDPR Art. 17):
//   (a) the FULL cascade — DEK-share destroy + vault.deleteBlob + injected
//       chain-port write — runs in order and is IRREVERSIBLE (a subsequent
//       reveal cannot reconstruct a DEK: shares gone + ciphertext gone);
//   (b) a `disabled`-authority PDA is REJECTED before anything is touched;
//   (c) a post-challenge reveal in progress (the mandatory
//       NOT-post-challenge-reveal-in-progress guardrail) BLOCKS the shred —
//       nothing destroyed;
//   plus the fail-closed edges: an already-finalized on-chain shred blocks, a
//   throwing guardrail read blocks (fail-closed, no destruction), and a
//   mid-cascade dependency failure surfaces loudly (never a silent success).
//
// All dependencies are injected fakes (no Postgres / no chain / no Redis needed)
// — the cascade ORDER + fail-closed behavior is what's under test here; the
// real DB/chain port impls are exercised by the integration suite.

import { describe, expect, it, vi } from "vitest";

import {
  ShredExecutionError,
  ShredExecutor,
  normalizeShredAuthority,
  type ShareRecordDestroyer,
  type ShredAuditWriter,
  type ShredExecutionRequest,
  type ShredExecutorChainPort,
} from "../../src/shred/shred-executor.js";
import type { ShredStateLivePort } from "../../src/reveal/reveal-coordinator-impl.js";
import type { CealisV3Vault, ShredAuthority } from "../../src/vault/cealis-v3-vault.js";
import type { Hex32 } from "../../src/types/reveal-artifact-bundle.js";

const H_COMMIT = `0x${"ab".repeat(32)}` as Hex32;
const PDA_ROOT = `0x${"cd".repeat(32)}` as Hex32;
const REASON = `0x${"ef".repeat(32)}` as Hex32;
const VAULT_REF = "vault://subject-demo/blob";

/**
 * Stand-in DEK-share store with destroy semantics + a getter so the test can
 * assert the shares are GONE post-cascade (the irreversibility check). The real
 * impl is `DELETE FROM dek_share_records WHERE h_commit`.
 */
function fakeShareStore(initialShareCount: number) {
  const shares = new Map<string, number>([[H_COMMIT, initialShareCount]]);
  const destroyer: ShareRecordDestroyer = {
    destroyShares: vi.fn(async (hCommit: Hex32) => {
      const had = shares.get(hCommit) ?? 0;
      shares.delete(hCommit);
      return had;
    }),
  };
  return { destroyer, remaining: (h: Hex32) => shares.get(h) ?? 0 };
}

/**
 * Stand-in vault that holds a single ciphertext blob and deletes it
 * irreversibly. Only the surface the executor touches (`deleteBlob`) is real;
 * the rest throw so an accidental use is loud.
 */
function fakeVault() {
  const blobs = new Map<string, true>([[VAULT_REF, true]]);
  const vault = {
    deleteBlob: vi.fn(async (input: { ref: string; shredAuthority: ShredAuthority }) => {
      if (!blobs.has(input.ref)) throw new Error("vault ref not found");
      blobs.delete(input.ref);
      return { ref: input.ref, shredded_at: "2026-06-02T00:00:00.000Z" };
    }),
    putBlob: notImpl("putBlob"),
    getBlob: notImpl("getBlob"),
    getRetentionStatus: notImpl("getRetentionStatus"),
    listExpired: notImpl("listExpired"),
  } as unknown as CealisV3Vault;
  return { vault, present: (ref: string) => blobs.has(ref) };
}

function notImpl(name: string) {
  return vi.fn(async () => {
    throw new Error(`unexpected ${name} call in shred test`);
  });
}

/** Chain port that records the recordShred call + returns a proof token. */
function fakeChainPort() {
  const port: ShredExecutorChainPort = {
    recordShred: vi.fn(async () => ({
      txHash: "0xtxhash",
      proofShred: `0x${"dd".repeat(32)}` as Hex32,
    })),
  };
  return port;
}

/** Append-only audit writer fake (records the row it would append). */
function fakeAuditWriter() {
  const rows: unknown[] = [];
  const writer: ShredAuditWriter = {
    appendShredAudit: vi.fn(async (input) => {
      rows.push(input);
    }),
  };
  return { writer, rows };
}

/** Shred-state port whose live read is settable per test. */
function fakeShredPort(
  live: { state: "none" | "requested" | "finalized"; post_challenge_reveal_in_progress: boolean } | (() => never),
): ShredStateLivePort {
  return {
    read: vi.fn(async () => {
      if (typeof live === "function") return live();
      return live;
    }),
  };
}

function buildRequest(overrides: Partial<ShredExecutionRequest> = {}): ShredExecutionRequest {
  return {
    hCommit: H_COMMIT,
    shredAuthority: "subject",
    vaultRef: VAULT_REF,
    pdaRoot: PDA_ROOT,
    reasonDigest: REASON,
    actorRef: "subject_demo",
    ...overrides,
  };
}

describe("normalizeShredAuthority", () => {
  it("maps the capitalized escrow enum to the lowercase vault enum", () => {
    expect(normalizeShredAuthority("Subject")).toBe("subject");
    expect(normalizeShredAuthority("Joint")).toBe("joint");
    expect(normalizeShredAuthority("Operator")).toBe("operator");
    expect(normalizeShredAuthority("Timelock")).toBe("timelock");
    expect(normalizeShredAuthority("Disabled")).toBe("disabled");
  });
});

describe("ShredExecutor — full crypto-shred cascade (irreversible)", () => {
  it("destroys shares, deletes the vault blob, writes on-chain, and appends audit — in order", async () => {
    const { destroyer, remaining } = fakeShareStore(3);
    const { vault, present } = fakeVault();
    const chainPort = fakeChainPort();
    const { writer, rows } = fakeAuditWriter();
    const shredPort = fakeShredPort({ state: "none", post_challenge_reveal_in_progress: false });

    const executor = new ShredExecutor({
      shredStatePort: shredPort,
      shareDestroyer: destroyer,
      vault,
      chainPort,
      auditWriter: writer,
      now: () => new Date("2026-06-02T12:00:00.000Z"),
    });

    const result = await executor.execute(buildRequest());

    // Guardrail read happened LIVE first.
    expect(shredPort.read).toHaveBeenCalledWith(H_COMMIT);

    // (2) DEK shares destroyed — IRREVERSIBLE: none remain.
    expect(destroyer.destroyShares).toHaveBeenCalledWith(H_COMMIT);
    expect(remaining(H_COMMIT)).toBe(0);
    expect(result.sharesDestroyed).toBe(3);

    // (3) Vault ciphertext deleted — IRREVERSIBLE: blob gone.
    expect(vault.deleteBlob).toHaveBeenCalledWith({ ref: VAULT_REF, shredAuthority: "subject" });
    expect(present(VAULT_REF)).toBe(false);

    // (4) On-chain ShredRegistry write (G1 refuse-future + G4 refuse) called.
    expect(chainPort.recordShred).toHaveBeenCalledWith({
      hCommit: H_COMMIT,
      pdaRoot: PDA_ROOT,
      reasonDigest: REASON,
    });
    expect(result.chainTxHash).toBe("0xtxhash");
    expect(result.proofShred).toBe(`0x${"dd".repeat(32)}`);

    // (5) Append-only audit row written keyed by h_commit (WHO/WHY).
    expect(writer.appendShredAudit).toHaveBeenCalledTimes(1);
    expect(rows[0]).toMatchObject({
      hCommit: H_COMMIT,
      shredAuthority: "subject",
      actorRef: "subject_demo",
    });
    expect(result.shreddedAt).toBe("2026-06-02T12:00:00.000Z");
  });

  it("threads the optional partner/pda/reason refs into the audit row when present", async () => {
    const { destroyer } = fakeShareStore(2);
    const { vault } = fakeVault();
    const { writer, rows } = fakeAuditWriter();
    const executor = new ShredExecutor({
      shredStatePort: fakeShredPort({ state: "none", post_challenge_reveal_in_progress: false }),
      shareDestroyer: destroyer,
      vault,
      chainPort: fakeChainPort(),
      auditWriter: writer,
    });

    await executor.execute(
      buildRequest({
        shredAuthority: "operator",
        actorRef: "partner_demo",
        partnerId: "partner_demo",
        pdaId: "pda_demo",
        requestReasonRef: "ticket-42",
      }),
    );

    expect(rows[0]).toMatchObject({
      partnerId: "partner_demo",
      pdaId: "pda_demo",
      requestReasonRef: "ticket-42",
      shredAuthority: "operator",
    });
  });
});

describe("ShredExecutor — disabled authority is rejected (erasure deliberately off)", () => {
  it("rejects a `disabled`-authority shred before touching shares / vault / chain", async () => {
    const { destroyer, remaining } = fakeShareStore(3);
    const { vault, present } = fakeVault();
    const chainPort = fakeChainPort();
    const { writer } = fakeAuditWriter();
    const shredPort = fakeShredPort({ state: "none", post_challenge_reveal_in_progress: false });

    const executor = new ShredExecutor({
      shredStatePort: shredPort,
      shareDestroyer: destroyer,
      vault,
      chainPort,
      auditWriter: writer,
    });

    await expect(executor.execute(buildRequest({ shredAuthority: "disabled" }))).rejects.toMatchObject({
      name: "ShredExecutionError",
      context: { reasonCode: "SHRED_AUTHORITY_DISABLED", step: "authority-check" },
    });

    // Nothing was touched — not even the live guardrail read.
    expect(shredPort.read).not.toHaveBeenCalled();
    expect(destroyer.destroyShares).not.toHaveBeenCalled();
    expect(vault.deleteBlob).not.toHaveBeenCalled();
    expect(chainPort.recordShred).not.toHaveBeenCalled();
    expect(writer.appendShredAudit).not.toHaveBeenCalled();
    expect(remaining(H_COMMIT)).toBe(3);
    expect(present(VAULT_REF)).toBe(true);
  });
});

describe("ShredExecutor — guardrail: post-challenge reveal in progress blocks the shred", () => {
  it("blocks the shred (mandatory NOT-post-challenge-reveal-in-progress guardrail) and destroys nothing", async () => {
    const { destroyer, remaining } = fakeShareStore(3);
    const { vault, present } = fakeVault();
    const chainPort = fakeChainPort();
    const { writer } = fakeAuditWriter();
    // ChallengeOpen → state "requested" + guardrail TRUE (T3.4 mapping).
    const shredPort = fakeShredPort({ state: "requested", post_challenge_reveal_in_progress: true });

    const executor = new ShredExecutor({
      shredStatePort: shredPort,
      shareDestroyer: destroyer,
      vault,
      chainPort,
      auditWriter: writer,
    });

    await expect(executor.execute(buildRequest())).rejects.toMatchObject({
      name: "ShredExecutionError",
      context: {
        reasonCode: "SHRED_BLOCKED_POST_CHALLENGE_REVEAL",
        step: "guardrail",
        postChallengeRevealInProgress: true,
      },
    });

    // The race-foreclosing guardrail means NOTHING destructive ran.
    expect(destroyer.destroyShares).not.toHaveBeenCalled();
    expect(vault.deleteBlob).not.toHaveBeenCalled();
    expect(chainPort.recordShred).not.toHaveBeenCalled();
    expect(remaining(H_COMMIT)).toBe(3);
    expect(present(VAULT_REF)).toBe(true);
  });

  it("blocks an already-finalized on-chain shred without re-running the cascade", async () => {
    const { destroyer } = fakeShareStore(3);
    const { vault } = fakeVault();
    const executor = new ShredExecutor({
      shredStatePort: fakeShredPort({ state: "finalized", post_challenge_reveal_in_progress: false }),
      shareDestroyer: destroyer,
      vault,
      chainPort: fakeChainPort(),
      auditWriter: fakeAuditWriter().writer,
    });

    await expect(executor.execute(buildRequest())).rejects.toMatchObject({
      context: { reasonCode: "SHRED_BLOCKED_ALREADY_FINALIZED", step: "guardrail" },
    });
    expect(destroyer.destroyShares).not.toHaveBeenCalled();
    expect(vault.deleteBlob).not.toHaveBeenCalled();
  });

  it("fails CLOSED when the live shred-state read throws (no permissive default)", async () => {
    const { destroyer } = fakeShareStore(3);
    const { vault } = fakeVault();
    const executor = new ShredExecutor({
      shredStatePort: fakeShredPort(() => {
        throw new Error("RPC down");
      }),
      shareDestroyer: destroyer,
      vault,
      chainPort: fakeChainPort(),
      auditWriter: fakeAuditWriter().writer,
    });

    await expect(executor.execute(buildRequest())).rejects.toBeInstanceOf(ShredExecutionError);
    // A blocked guardrail means no destruction.
    expect(destroyer.destroyShares).not.toHaveBeenCalled();
    expect(vault.deleteBlob).not.toHaveBeenCalled();
  });
});

describe("ShredExecutor — mid-cascade failure surfaces loudly (never a silent success)", () => {
  it("surfaces a vault-delete failure with the shares-destroyed count for reconcile", async () => {
    const { destroyer, remaining } = fakeShareStore(3);
    const vault = {
      deleteBlob: vi.fn(async () => {
        throw new Error("vault backend down");
      }),
    } as unknown as CealisV3Vault;
    const chainPort = fakeChainPort();
    const { writer } = fakeAuditWriter();

    const executor = new ShredExecutor({
      shredStatePort: fakeShredPort({ state: "none", post_challenge_reveal_in_progress: false }),
      shareDestroyer: destroyer,
      vault,
      chainPort,
      auditWriter: writer,
    });

    await expect(executor.execute(buildRequest())).rejects.toMatchObject({
      name: "ShredExecutionError",
      context: { reasonCode: "SHRED_VAULT_DELETE_FAILED", step: "vault-delete", sharesDestroyed: 3 },
    });

    // Shares are ALREADY destroyed (the irreversible step ran) — but the chain
    // write + audit did NOT, and the error is loud (not a 2xx).
    expect(remaining(H_COMMIT)).toBe(0);
    expect(chainPort.recordShred).not.toHaveBeenCalled();
    expect(writer.appendShredAudit).not.toHaveBeenCalled();
  });

  it("surfaces an on-chain write failure after shares + vault are already gone", async () => {
    const { destroyer } = fakeShareStore(3);
    const { vault } = fakeVault();
    const chainPort: ShredExecutorChainPort = {
      recordShred: vi.fn(async () => {
        throw new Error("chain revert");
      }),
    };
    const { writer } = fakeAuditWriter();
    const executor = new ShredExecutor({
      shredStatePort: fakeShredPort({ state: "none", post_challenge_reveal_in_progress: false }),
      shareDestroyer: destroyer,
      vault,
      chainPort,
      auditWriter: writer,
    });

    await expect(executor.execute(buildRequest())).rejects.toMatchObject({
      context: { reasonCode: "SHRED_CHAIN_WRITE_FAILED", step: "chain-write" },
    });
    expect(writer.appendShredAudit).not.toHaveBeenCalled();
  });
});
