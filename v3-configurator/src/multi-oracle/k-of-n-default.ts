export interface KOfNDefault {
  readonly k: number;
  readonly n: number;
  readonly required_oracle_ops: number;
}

const DEFAULTS: Record<string, KOfNDefault> = {
  testament: { k: 2, n: 3, required_oracle_ops: 2 },
  irreversible_personal_reveal: { k: 2, n: 3, required_oracle_ops: 2 },
  evidence: { k: 2, n: 3, required_oracle_ops: 2 },
  tamper_proof_retention: { k: 2, n: 3, required_oracle_ops: 2 },
  archival: { k: 2, n: 3, required_oracle_ops: 2 },
  m_and_a: { k: 2, n: 4, required_oracle_ops: 2 },
  multi_party_commercial_escrow: { k: 2, n: 4, required_oracle_ops: 2 },
  dead_man_switch: { k: 2, n: 3, required_oracle_ops: 2 },
  conditional_reveal_liveness: { k: 2, n: 3, required_oracle_ops: 2 },
};

export function normalizeArchetype(value: string): string {
  return value.toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
}

export function getKOfNDefault(
  archetype: string | undefined,
): KOfNDefault | null {
  if (archetype === undefined) return null;
  return DEFAULTS[normalizeArchetype(archetype)] ?? null;
}

export function isIrreversibleExternalTriggerArchetype(
  archetype: string | undefined,
): boolean {
  return getKOfNDefault(archetype) !== null;
}
