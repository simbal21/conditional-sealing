// LOCAL gate keypair store + share-load/unwrap source (Phase-3 EXTERNAL-GATE
// default — build TO, do NOT cross).
//
// In production the per-gate recipient KEM keypairs live INSIDE each gate's TEE /
// threshold network: the registry publishes the PUBLIC key (per-commit ephemeral
// for Lit/G4/Conditional, long-lived committee for drand), the PRIVATE key never
// leaves the enclave, and the unwrap happens inside the enclave at reveal. THIS
// module is the local stand-in for that enclave boundary so the real-stack E2E
// runs end-to-end on one machine: it generates a per-commit gate keypair set at
// ingest, exposes the PUBLIC keys to the ingest writer (to wrap each share to its
// gate) and the PRIVATE keys to the reveal gate clients (to unwrap their stanza).
//
// SECURITY POSTURE OF THE LOCAL STAND-IN (reported, not hidden): locally the gate
// private keys DO live in this process — that is the explicit, documented
// consequence of running every gate on one box without real TEEs. It does NOT
// weaken the architecture: the wrapped material is the ONLY thing persisted, the
// unwrap is keyed per-gate, and a single gate's share is zero info on the DEK
// (Shamir). The non-custody guarantee that this module proves is "the SERVER's
// DURABLE STATE (the DB: vault blob + dek_share_records) cannot reconstruct the
// DEK without the gate private keys" — which holds because the private keys are
// NEVER written to the DB. In production the private keys are additionally absent
// from the host process entirely (enclave-resident). The adversarial E2E asserts
// the durable-state property, which is the load-bearing one.
//
// V3 isolation: crypto from @cealis/v3-crypto; no @cealis/shared, no V1 env vars.

import {
  generateHybridWrapRecipientKeypair,
  type HybridWrapRecipientPrivateKeys,
  type HybridWrapRecipientPublicKeys,
} from "../m1-imports.js";
import type { Hex32 } from "../h-commit/index.js";
import {
  gateRecipientKey,
  type G3Choice,
  type GateRecipientPubkeyMap,
} from "../ingest/wrap-shares.js";
import type {
  AccessStructureProfile,
} from "../m1-imports.js";
import type {
  GateRecipientKeyProvider,
} from "../ingest/vault-writer-impl.js";
import type {
  GateStanzaUnwrapSource,
  GateWrappedStanza,
} from "../combiner-orchestrator/gate-unwrap.js";

/** GateKind numeric values (mirror M2 Enums.sol). */
const GATE_LIT = 0;
const GATE_DCIPHER = 1;
const GATE_DRAND = 2;
const GATE_G4 = 3;
const GATE_CONDITIONAL = 4;

interface GateKeypair {
  readonly priv: HybridWrapRecipientPrivateKeys;
  readonly pub: HybridWrapRecipientPublicKeys;
}

function generateGateKeypair(): GateKeypair {
  const priv: HybridWrapRecipientPrivateKeys = generateHybridWrapRecipientKeypair();
  return { priv, pub: { pk_x25519: priv.pk_x25519, pk_mlkem: priv.pk_mlkem } };
}

/** The gate slots a profile + g3_choice participates in (the keyset to generate). */
function gateSlotsForProfile(
  profile: AccessStructureProfile,
  g3Choice: G3Choice,
): readonly { gateKind: number; conditionalRecipientIndex: number }[] {
  const g3 = g3Choice === "dcipher" ? GATE_DCIPHER : GATE_DRAND;
  const slots: { gateKind: number; conditionalRecipientIndex: number }[] = [
    { gateKind: GATE_LIT, conditionalRecipientIndex: 0 },
    { gateKind: g3, conditionalRecipientIndex: 0 },
    { gateKind: GATE_G4, conditionalRecipientIndex: 0 },
  ];
  if (profile.kind === "RECIPIENT_1_OF_1") {
    slots.push({ gateKind: GATE_CONDITIONAL, conditionalRecipientIndex: 0 });
  } else if (profile.kind === "RECIPIENT_K_OF_N") {
    for (let i = 0; i < profile.n_conditional; i++) {
      slots.push({ gateKind: GATE_CONDITIONAL, conditionalRecipientIndex: i });
    }
  }
  return slots;
}

/**
 * In-process gate keypair store shared between the ingest writer (pubkeys → wrap)
 * and the reveal gate clients (privkeys → unwrap). One per composition root.
 * Keyed by `(h_commit, gateKind, crIndex)`. Stands in for the per-gate enclave
 * boundary locally. The wrap/AEAD context digests are PUBLIC and travel with the
 * wrapped stanza in `dek_share_records` (loaded by the `WrappedStanzaLoader`), so
 * this store holds ONLY the secret gate private keys.
 */
export class LocalGateKeyStore {
  /** `${h_commit}|${gateKind}:${cr}` → keypair. */
  private readonly keys = new Map<string, GateKeypair>();

  private keyId(hCommit: Hex32, gateKind: number, conditionalRecipientIndex: number): string {
    return `${hCommit}|${gateKind}:${conditionalRecipientIndex}`;
  }

  /**
   * The `GateRecipientKeyProvider` the ingest writer uses: generate (idempotent)
   * the per-commit gate keypairs and return the PUBLIC key map for wrapping.
   */
  recipientKeyProvider(): GateRecipientKeyProvider {
    return {
      resolve: (input): GateRecipientPubkeyMap => {
        const map = new Map<string, HybridWrapRecipientPublicKeys>();
        for (const slot of gateSlotsForProfile(input.profile, input.g3Choice)) {
          const id = this.keyId(input.h_commit, slot.gateKind, slot.conditionalRecipientIndex);
          let kp = this.keys.get(id);
          if (kp === undefined) {
            kp = generateGateKeypair();
            this.keys.set(id, kp);
          }
          map.set(gateRecipientKey(slot.gateKind, slot.conditionalRecipientIndex), kp.pub);
        }
        return map;
      },
    };
  }

  /**
   * The `GateStanzaUnwrapSource` the reveal gate clients use: load the wrapped
   * stanza from the DB (via the injected loader) + supply the gate PRIVATE key.
   */
  unwrapSource(loadStanza: WrappedStanzaLoader): GateStanzaUnwrapSource {
    return {
      resolve: async (input) => {
        const id = this.keyId(input.hCommit, input.gateKind, input.conditionalRecipientIndex);
        const kp = this.keys.get(id);
        if (kp === undefined) {
          throw new Error(
            `LocalGateKeyStore: no gate private key for ${id} — the gate cannot unwrap its ` +
              "stanza (key was never registered at ingest).",
          );
        }
        const stanza: GateWrappedStanza = await loadStanza({
          hCommit: input.hCommit,
          gateKind: input.gateKind,
          conditionalRecipientIndex: input.conditionalRecipientIndex,
        });
        return { stanza, recipient: kp.priv };
      },
    };
  }
}

/** Loads the full wrapped stanza (payload + routing + public digests) for one
 *  gate from `dek_share_records`. Returns no key material — the wrapped payload
 *  is opaque without that gate's private key. */
export type WrappedStanzaLoader = (input: {
  readonly hCommit: Hex32;
  readonly gateKind: number;
  readonly conditionalRecipientIndex: number;
}) => Promise<GateWrappedStanza>;
