import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { arrayValue, isRecord, makeCiFailure, stringValue, valueClass } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-17")!; // verbatim spec anchor

function invalidEntry(entry: unknown): boolean {
  if (!isRecord(entry)) return false;
  const gateKind = stringValue(entry["gate_kind"]);
  const lifecycle = stringValue(entry["lifecycle"]);
  if (gateKind === "drand") return lifecycle === "per_commit_ephemeral";
  if (gateKind === "lit" || gateKind === "g4" || gateKind === "conditional") {
    return lifecycle === "long_lived";
  }
  return false;
}

export function checkCi17(pda: SubmittedPda): DualFormValidationFailure | null {
  const entries = arrayValue(pda["gate_recipient_pubkeys"]);
  if (!entries.some((entry) => invalidEntry(entry))) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "gate_recipient_pubkey_lifecycle",
    code: "GATE_PUBKEY_LIFECYCLE_INVALID",
    source_field_path: "gate_recipient_pubkeys",
    failed_predicate: "drand is not per-commit ephemeral; Lit/G4/Conditional are not long-lived KEM mode",
    sanitized_value_class: valueClass(entries),
    cross_references: "S2-3 §2.5 gate-recipient pubkey lifecycle; S2-4 §4.3 CI-17",
    why_failed:
      "This configuration assigns a gate-recipient pubkey lifecycle that contradicts the gate kind.",
    partner_action_text: "Use long-lived committee mode for drand and per-commit ephemeral mode for Lit, G4, and conditional recipients.",
  });
}
