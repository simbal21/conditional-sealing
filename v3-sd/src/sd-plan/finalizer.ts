import type { CommitStore } from "../commit/commit-store.js";

export interface SdExecutionSecrets {
  readonly plaintext?: Record<string, unknown>;
  readonly normalized_payload?: Record<string, unknown> | null;
  readonly sd_master_salt?: Uint8Array | null;
  readonly field_salts?: ReadonlyArray<Uint8Array>;
  readonly encoded_values?: ReadonlyArray<{ readonly bytes?: Uint8Array }>;
  readonly commit_store?: CommitStore;
  readonly witness_buffers?: ReadonlyArray<Uint8Array>;
  readonly tmpfs_artifacts?: ReadonlyArray<{ wipe(): void }>;
}

export function zeroizeUint8(bytes: Uint8Array | null | undefined): void {
  if (bytes) bytes.fill(0);
}

export function finalizeSdExecution(secrets: SdExecutionSecrets): void {
  zeroizeRecord(secrets.plaintext);
  zeroizeRecord(secrets.normalized_payload ?? undefined);
  zeroizeUint8(secrets.sd_master_salt);
  for (const salt of secrets.field_salts ?? []) zeroizeUint8(salt);
  for (const encoded of secrets.encoded_values ?? []) zeroizeUint8(encoded.bytes);
  secrets.commit_store?.zeroizeSalts();
  for (const witness of secrets.witness_buffers ?? []) zeroizeUint8(witness);
  for (const artifact of secrets.tmpfs_artifacts ?? []) artifact.wipe();
}

function zeroizeRecord(record: Record<string, unknown> | undefined): void {
  if (!record) return;
  for (const key of Object.keys(record)) record[key] = null;
}
