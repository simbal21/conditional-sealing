import type { CommitAADInput } from "../m1-imports.js";
import {
  GateKind,
  isGateRecipientPubkeySignableAt,
  type GateRecipientPubkeyEntry,
} from "../types/gate-recipient.js";
import type {
  AccessStructureProfile,
  CommitRegistrySnapshot,
  SigmaEvidenceBundle,
} from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { bytesEqual } from "./jcs-canonicalize.js";

export function verifyGateRecipientPubkeys(input: {
  readonly authorizationId: string;
  readonly commitAAD: CommitAADInput;
  readonly profile: AccessStructureProfile;
  readonly sigmas: SigmaEvidenceBundle;
  readonly commitSnapshot: CommitRegistrySnapshot;
}): void {
  for (const required of requiredGateKeys(input.commitAAD, input.profile)) {
    const snapshotEntry = input.commitSnapshot.gateRecipientPubkeys.get(required.key);
    if (snapshotEntry === undefined) {
      throw gatePubkeyError(`missing gate-recipient pubkey snapshot for ${required.key}`);
    }
    assertEntryUsable(snapshotEntry, required.gateKind, required.conditionalRecipientIndex, input.sigmas.commitBlock);
  }

  for (const evidence of input.sigmas.evidence) {
    const key = gateKey(evidence.gateKind, evidence.conditionalRecipientIndex);
    const snapshotEntry = input.commitSnapshot.gateRecipientPubkeys.get(key);
    if (snapshotEntry === undefined) throw gatePubkeyError(`extra σ not bound by commit profile: ${key}`);
    assertEntryMatchesEvidence(snapshotEntry, evidence.gateRecipientPubkey);
  }
}

export function gateKey(gateKind: GateKind, conditionalRecipientIndex: number): string {
  return `${gateKind}:${conditionalRecipientIndex}`;
}

function requiredGateKeys(
  commitAAD: CommitAADInput,
  profile: AccessStructureProfile,
): readonly { readonly key: string; readonly gateKind: GateKind; readonly conditionalRecipientIndex: number }[] {
  const g3Kind = commitAAD.g3_choice === 0 ? GateKind.Dcipher : GateKind.Drand;
  const required: { key: string; gateKind: GateKind; conditionalRecipientIndex: number }[] = [
    { key: gateKey(GateKind.LitV3, 0), gateKind: GateKind.LitV3, conditionalRecipientIndex: 0 },
    { key: gateKey(g3Kind, 0), gateKind: g3Kind, conditionalRecipientIndex: 0 },
    { key: gateKey(GateKind.G4, 0), gateKind: GateKind.G4, conditionalRecipientIndex: 0 },
  ];
  if (profile.kind === "RECIPIENT_1_OF_1") {
    required.push({
      key: gateKey(GateKind.ConditionalRecipient, 0),
      gateKind: GateKind.ConditionalRecipient,
      conditionalRecipientIndex: 0,
    });
  }
  if (profile.kind === "RECIPIENT_K_OF_N") {
    for (let i = 0; i < profile.n_conditional; i++) {
      required.push({
        key: gateKey(GateKind.ConditionalRecipient, i),
        gateKind: GateKind.ConditionalRecipient,
        conditionalRecipientIndex: i,
      });
    }
  }
  return required;
}

function assertEntryUsable(
  entry: GateRecipientPubkeyEntry,
  expectedGateKind: GateKind,
  expectedConditionalRecipientIndex: number,
  commitBlock: bigint,
): void {
  if (entry.gateKind !== expectedGateKind || entry.conditionalRecipientIndex !== expectedConditionalRecipientIndex) {
    throw gatePubkeyError("gate-recipient pubkey snapshot returned wrong gate kind or conditional index");
  }
  if (!isGateRecipientPubkeySignableAt(entry, commitBlock)) {
    throw gatePubkeyError("gate-recipient pubkey was not signable at commit block");
  }
}

function assertEntryMatchesEvidence(
  snapshotEntry: GateRecipientPubkeyEntry,
  evidenceEntry: GateRecipientPubkeyEntry,
): void {
  if (
    snapshotEntry.authorizationId !== evidenceEntry.authorizationId ||
    snapshotEntry.gateKind !== evidenceEntry.gateKind ||
    snapshotEntry.conditionalRecipientIndex !== evidenceEntry.conditionalRecipientIndex ||
    snapshotEntry.attestationRef !== evidenceEntry.attestationRef ||
    !bytesEqual(snapshotEntry.kemPubkey, evidenceEntry.kemPubkey)
  ) {
    throw gatePubkeyError("sigma evidence gate-recipient pubkey does not match commit-block snapshot");
  }
}

function gatePubkeyError(message: string): CustodyError {
  return new CustodyError(
    CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
    message,
  );
}
