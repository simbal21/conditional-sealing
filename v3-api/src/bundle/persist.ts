import type { CombinerManifest } from "../types/combiner-manifest.js";
import type { Hex32, RevealArtifactBundle } from "../types/reveal-artifact-bundle.js";

export type RevealDeliveryStatus =
  | "authorized"
  | "manifest_ready"
  | "ready_for_gate_signing"
  | "finalized"
  | "failed"
  | "deferred"
  | "refused";

export interface PersistedBundleRecord {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly recipient_ref: string;
  readonly bundle_digest: Hex32;
  readonly bundle_storage_ref: string;
  readonly status: RevealDeliveryStatus;
  readonly finalized_at?: string;
  readonly bundle: RevealArtifactBundle;
}

export interface RevealStatusRecord {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly status: RevealDeliveryStatus;
  readonly g4_phase: 1 | 2;
  readonly challenge_window_expired_at?: string;
  readonly refusal?: Record<string, unknown>;
  readonly artifact_bundles?: readonly {
    readonly recipient_ref: string;
    readonly bundle_digest: Hex32;
    readonly bundle_storage_ref: string;
    readonly status: RevealDeliveryStatus;
  }[];
}

export interface RevealArtifactRepository {
  upsertStatus(status: RevealStatusRecord): Promise<void>;
  getStatus(authorizationId: Hex32): Promise<RevealStatusRecord | undefined>;
  putManifest(authorizationId: Hex32, manifest: CombinerManifest): Promise<void>;
  getManifest(authorizationId: Hex32): Promise<CombinerManifest | undefined>;
  putBundle(record: PersistedBundleRecord): Promise<void>;
  getBundle(authorizationId: Hex32, recipientRef: string): Promise<PersistedBundleRecord | undefined>;
  listBundles(authorizationId: Hex32): Promise<readonly PersistedBundleRecord[]>;
}

export class InMemoryRevealArtifactRepository implements RevealArtifactRepository {
  private readonly statuses = new Map<Hex32, RevealStatusRecord>();
  private readonly manifests = new Map<Hex32, CombinerManifest>();
  private readonly bundles = new Map<string, PersistedBundleRecord>();

  async upsertStatus(status: RevealStatusRecord): Promise<void> {
    this.statuses.set(status.authorizationId, status);
  }

  async getStatus(authorizationId: Hex32): Promise<RevealStatusRecord | undefined> {
    return this.statuses.get(authorizationId);
  }

  async putManifest(authorizationId: Hex32, manifest: CombinerManifest): Promise<void> {
    this.manifests.set(authorizationId, manifest);
  }

  async getManifest(authorizationId: Hex32): Promise<CombinerManifest | undefined> {
    return this.manifests.get(authorizationId);
  }

  async putBundle(record: PersistedBundleRecord): Promise<void> {
    this.bundles.set(bundleKey(record.authorizationId, record.recipient_ref), record);
    const current = this.statuses.get(record.authorizationId);
    const existingBundles = current?.artifact_bundles ?? [];
    const remaining = existingBundles.filter((bundle) => bundle.recipient_ref !== record.recipient_ref);
    this.statuses.set(record.authorizationId, {
      authorizationId: record.authorizationId,
      h_commit: record.h_commit,
      status: "finalized",
      g4_phase: record.bundle.sigma_block.sigma_g4.phase ?? current?.g4_phase ?? 2,
      challenge_window_expired_at:
        current?.challenge_window_expired_at ?? record.bundle.authorization.challenge_window_expired_at,
      refusal: current?.refusal,
      artifact_bundles: [
        ...remaining,
        {
          recipient_ref: record.recipient_ref,
          bundle_digest: record.bundle_digest,
          bundle_storage_ref: record.bundle_storage_ref,
          status: record.status,
        },
      ],
    });
  }

  async getBundle(
    authorizationId: Hex32,
    recipientRef: string,
  ): Promise<PersistedBundleRecord | undefined> {
    return this.bundles.get(bundleKey(authorizationId, recipientRef));
  }

  async listBundles(authorizationId: Hex32): Promise<readonly PersistedBundleRecord[]> {
    return Array.from(this.bundles.values()).filter((record) => record.authorizationId === authorizationId);
  }
}

export function bundleStorageRef(authorizationId: Hex32, recipientRef: string): string {
  return `vault://reveal-artifacts/${authorizationId}/${encodeURIComponent(recipientRef)}`;
}

function bundleKey(authorizationId: Hex32, recipientRef: string): string {
  return `${authorizationId}:${recipientRef}`;
}
