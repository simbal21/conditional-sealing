import { checkOracleTierConsistency } from "../trust-tier/oracle-tier-consistency.js";
import {
  archetypeKey,
  getTrustTier,
  stableUniqueCount,
} from "../validate/cross-field/helpers.js";
import type {
  CrossFieldPda,
  MultiPartySignalConfig,
} from "../validate/cross-field/types.js";
import {
  getKOfNDefault,
  isIrreversibleExternalTriggerArchetype,
} from "./k-of-n-default.js";

export interface Cf07EnforcementInput {
  readonly pda: CrossFieldPda;
  readonly signal: MultiPartySignalConfig | null;
  readonly tier_c_acknowledgment_bound?: boolean;
}

export interface Cf07EnforcementResult {
  readonly ok: boolean;
  readonly reasons: readonly string[];
}

export function requiresMultiPartySignalDefault(pda: CrossFieldPda): boolean {
  const key = archetypeKey(pda);
  if (!isIrreversibleExternalTriggerArchetype(key)) return false;
  if (pda.firing_condition_depends_on_external_event_source === true)
    return true;
  const module = pda.reveal_condition?.module;
  return (
    module === "MultiPartySignal" ||
    module === "OracleAttestation" ||
    module === "DeadManSwitch" ||
    key.includes("testament") ||
    key.includes("m_and_a")
  );
}

export function enforceMultiPartySignalDefault(
  input: Cf07EnforcementInput,
): Cf07EnforcementResult {
  const reasons: string[] = [];
  const defaultConfig = getKOfNDefault(archetypeKey(input.pda));
  if (defaultConfig === null) return { ok: true, reasons };
  const signal = input.signal;
  if (signal === null) {
    return { ok: false, reasons: ["missing MultiPartySignal default"] };
  }

  const k = signal.k;
  const n = signal.n;
  if (k === undefined || n === undefined) {
    reasons.push("missing MultiPartySignal k or n");
  } else {
    if (k < defaultConfig.k)
      reasons.push(
        "MultiPartySignal k is below irreversible-archetype default k >= 2",
      );
    if (k > n) reasons.push("MultiPartySignal k > n");
  }

  const signerIdentities =
    signal.signer_identities ??
    signal.oracle_refs?.map(
      (ref) => ref.signer_identity ?? ref.oracle_id ?? ref.id ?? "",
    ) ??
    [];
  const signerIdentitiesPresent = signerIdentities.filter(
    (identity) => identity.length > 0,
  );
  if (
    signerIdentitiesPresent.length > stableUniqueCount(signerIdentitiesPresent)
  ) {
    reasons.push("duplicate signer identities");
  }

  const operatorIds =
    signal.operator_ids ??
    signal.oracle_refs?.map(
      (ref) => ref.operator_id ?? ref.oracle_id ?? ref.id ?? "",
    ) ??
    [];
  const operatorIdsPresent = operatorIds.filter(
    (operator) => operator.length > 0,
  );
  const enoughOperators =
    operatorIdsPresent.length >= defaultConfig.required_oracle_ops;
  if (
    signal.independent_operators !== true ||
    !enoughOperators ||
    operatorIdsPresent.length > stableUniqueCount(operatorIdsPresent)
  ) {
    reasons.push("non-independent oracle operators");
  }

  const tierResult = checkOracleTierConsistency({
    declared_tier: getTrustTier(input.pda),
    oracle_refs: signal.oracle_refs ?? [],
    tier_c_acknowledgment_bound: input.tier_c_acknowledgment_bound === true,
  });
  if (!tierResult.ok)
    reasons.push(
      ...tierResult.reasons.map(
        (reason) => `oracle refs below declared trust tier: ${reason}`,
      ),
    );

  if (signal.signal_digest_bound !== true) {
    reasons.push("missing signal-digest binding");
  }

  return { ok: reasons.length === 0, reasons };
}
