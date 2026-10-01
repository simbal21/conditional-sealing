// FilesystemBackend — opaque-byte storage seam over a local directory tree.
// Pure key→bytes storage with NO commit-binding / retention / shred-authority
// semantics (those live one layer up in CealisV3VaultImpl). Ships as a real
// backend for local / single-node deployments and as the S2-5 backend-agnostic
// proof that the vault is not hardcoded to Postgres; S3/R2/IPFS are later
// external-gate backends behind the same `VaultBackend` shape.
//
// NOT an in-memory dev-shortcut (Rule 12): bytes are persisted to disk and
// survive process restart. The vault ref is mapped to a safe, collision-free
// on-disk filename by hashing the opaque ref (the ref scheme contains `/`, `:`
// and url-encoded segments that are not directly filesystem-safe).
//
// V3 isolation (SECURITY.md): no @cealis/shared, no ../../packages/*
// (V1), no V1 env vars. Caller injects the root directory at the composition
// root — the backend never reads an env var or a key file.

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { VaultBackend, VaultBackendId } from "../cealis-v3-vault.js";

export interface FilesystemBackendOptions {
  /** Root directory under which ciphertext blobs are written. Created on demand. */
  readonly rootDir: string;
}

const CIPHERTEXT_EXT = ".bin";
const REFMAP_EXT = ".ref";

/** Deterministic, collision-free, filesystem-safe filename for an opaque ref:
 *  the lowercase hex sha256 of the ref bytes. Same ref → same file (idempotent). */
function refToFileBase(ref: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(ref)));
}

export class FilesystemBackend implements VaultBackend {
  readonly backendId: VaultBackendId = "filesystem";
  private readonly rootDir: string;

  constructor(options: FilesystemBackendOptions) {
    this.rootDir = options.rootDir;
  }

  private ciphertextPath(ref: string): string {
    return join(this.rootDir, refToFileBase(ref) + CIPHERTEXT_EXT);
  }

  /** Sidecar mapping file storing the original opaque ref, so `listKeys` can
   *  return the caller's refs (not the on-disk hashes) and honor prefix filters. */
  private refmapPath(ref: string): string {
    return join(this.rootDir, refToFileBase(ref) + REFMAP_EXT);
  }

  async put(key: string, bytes: Uint8Array): Promise<void> {
    await mkdir(this.rootDir, { recursive: true });
    await writeFile(this.ciphertextPath(key), bytes);
    await writeFile(this.refmapPath(key), key, "utf-8");
  }

  async get(key: string): Promise<Uint8Array | undefined> {
    try {
      const buf = await readFile(this.ciphertextPath(key));
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw err;
    }
  }

  async delete(key: string): Promise<void> {
    await rm(this.ciphertextPath(key), { force: true });
    await rm(this.refmapPath(key), { force: true });
  }

  async listKeys(prefix?: string): Promise<readonly string[]> {
    let entries: string[];
    try {
      entries = await readdir(this.rootDir);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const refs: string[] = [];
    for (const entry of entries) {
      if (!entry.endsWith(REFMAP_EXT)) continue;
      const ref = await readFile(join(this.rootDir, entry), "utf-8");
      if (prefix === undefined || ref.startsWith(prefix)) refs.push(ref);
    }
    return refs;
  }
}
