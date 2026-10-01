// FilesystemVaultStore — the atomic `VaultStore` over a local directory tree.
// Ciphertext bytes via a composed `FilesystemBackend`; the inseparable commit
// binding + non-secret metadata in a per-ref JSON sidecar; crypto-shred deletes
// both AND appends a shred row to an append-only JSONL audit log.
//
// This is a REAL backend (Rule 12) — bytes + sidecar persist to disk and survive
// restart; it is NOT an in-memory dev shortcut. It is the S2-5 backend-agnostic
// proof (the vault layer is not hardcoded to Postgres) and the unit-test path
// that needs no Postgres instance.
//
// GDPR discipline (NON-NEGOTIABLE):
//   - The `.bin` file holds AEAD ciphertext ONLY — no plaintext, no DEK, ever.
//   - The sidecar JSON holds binding + non-secret metadata ONLY — no key, no PII.
//   - The shred audit JSONL is append-only by convention (open-append, never
//     rewritten) and carries NO PII: opaque ref + shred authority + timestamp.
//
// C1 inseparability: the sidecar (binding) and the `.bin` (ciphertext) are
// written together in `putRecord` and deleted together in `deleteRecord`;
// `getRecord` returns ciphertext + binding as ONE record or `undefined`.
//
// V3 isolation (SECURITY.md): no @cealis/shared, no V1 packages, no
// V1 env vars. Caller injects the root dir at the composition root.

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { appendFile, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { VaultBackendId, VaultBlob, VaultBlobMeta, VaultRef } from "../cealis-v3-vault.js";
import type {
  VaultShredAuditRow,
  VaultStore,
  VaultStorePutResult,
  VaultStoreRecord,
} from "../vault-store.js";
import { FilesystemBackend } from "./filesystem.js";

export interface FilesystemVaultStoreOptions {
  /** Root directory for ciphertext `.bin` files, `.meta.json` sidecars, and the
   *  append-only shred audit JSONL. Created on demand. */
  readonly rootDir: string;
}

const META_EXT = ".meta.json";
const SHRED_AUDIT_FILE = "shred-audit.jsonl";

interface SidecarJson {
  readonly ref: VaultRef;
  readonly commit_aad_bytes_hex: string;
  readonly commit_version_onwire: number;
  readonly commit_aad_digest: string;
  readonly meta: VaultBlobMeta;
}

function refToFileBase(ref: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(ref)));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export class FilesystemVaultStore implements VaultStore {
  readonly backendId: VaultBackendId = "filesystem";
  private readonly rootDir: string;
  private readonly backend: FilesystemBackend;

  constructor(options: FilesystemVaultStoreOptions) {
    this.rootDir = options.rootDir;
    this.backend = new FilesystemBackend({ rootDir: options.rootDir });
  }

  private metaPath(ref: string): string {
    return join(this.rootDir, refToFileBase(ref) + META_EXT);
  }

  private async readSidecar(ref: string): Promise<SidecarJson | undefined> {
    try {
      const raw = await readFile(this.metaPath(ref), "utf-8");
      return JSON.parse(raw) as SidecarJson;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw err;
    }
  }

  async putRecord(record: VaultStoreRecord): Promise<VaultStorePutResult> {
    const existingSidecar = await this.readSidecar(record.ref);
    if (existingSidecar) {
      const existingCiphertext = await this.backend.get(record.ref);
      const sameCiphertext =
        existingCiphertext !== undefined && bytesEqual(existingCiphertext, record.ciphertext);
      const sameBinding = bytesEqual(
        hexToBytes(existingSidecar.commit_aad_bytes_hex),
        record.commitBinding.commit_aad_bytes,
      );
      if (sameCiphertext && sameBinding) {
        return { stored: false, collision: false };
      }
      return { stored: false, collision: true };
    }

    await mkdir(this.rootDir, { recursive: true });
    // Ciphertext first, then the inseparable sidecar — both required for a valid
    // record (getRecord checks both are present).
    await this.backend.put(record.ref, record.ciphertext);
    const sidecar: SidecarJson = {
      ref: record.ref,
      commit_aad_bytes_hex: bytesToHex(record.commitBinding.commit_aad_bytes),
      commit_version_onwire: record.commitBinding.commit_version_onwire,
      commit_aad_digest: record.commitBinding.commit_aad_digest,
      meta: record.meta,
    };
    await writeFile(this.metaPath(record.ref), JSON.stringify(sidecar), "utf-8");
    return { stored: true, collision: false };
  }

  async getRecord(ref: VaultRef): Promise<VaultBlob | undefined> {
    const sidecar = await this.readSidecar(ref);
    if (!sidecar) return undefined;
    const ciphertext = await this.backend.get(ref);
    if (ciphertext === undefined) return undefined;
    return {
      ciphertext,
      commitBinding: {
        commit_aad_bytes: hexToBytes(sidecar.commit_aad_bytes_hex),
        commit_version_onwire: sidecar.commit_version_onwire,
        commit_aad_digest: sidecar.commit_aad_digest,
      },
      meta: sidecar.meta,
    };
  }

  async deleteRecord(audit: VaultShredAuditRow): Promise<boolean> {
    const sidecar = await this.readSidecar(audit.ref);
    if (!sidecar) return false;
    await this.backend.delete(audit.ref);
    await rm(this.metaPath(audit.ref), { force: true });
    // Append-only shred audit (NO PII).
    await mkdir(this.rootDir, { recursive: true });
    const auditLine =
      JSON.stringify({
        action: "vault_shred",
        vault_ref: audit.ref,
        shred_authority: audit.shredAuthority,
        shredded_at: audit.shreddedAt,
      }) + "\n";
    await appendFile(join(this.rootDir, SHRED_AUDIT_FILE), auditLine, "utf-8");
    return true;
  }

  async getMeta(ref: VaultRef): Promise<VaultBlobMeta | undefined> {
    const sidecar = await this.readSidecar(ref);
    return sidecar?.meta;
  }

  async listExpired(asOf: string): Promise<readonly VaultRef[]> {
    const cutoffMs = Date.parse(asOf);
    let entries: string[];
    try {
      entries = await readdir(this.rootDir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const expired: VaultRef[] = [];
    for (const entry of entries) {
      if (!entry.endsWith(META_EXT)) continue;
      const raw = await readFile(join(this.rootDir, entry), "utf-8");
      const sidecar = JSON.parse(raw) as SidecarJson;
      if (Date.parse(sidecar.meta.retention_expires_at) <= cutoffMs) {
        expired.push(sidecar.ref);
      }
    }
    return expired;
  }
}
