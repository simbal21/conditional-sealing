export type UseCaseKey =
  | "kyc"
  | "kyc_lending"
  | "m_and_a"
  | "regulated_eu"
  | "evidence"
  | "testament"
  | "time_lock"
  | "archival"
  | "dead_man_switch"
  | "long_retention";

export type DefaultValue = string | number | boolean;
export type DefaultRecord = Readonly<Record<string, DefaultValue>>;

export const USE_CASE_DEFAULTS: Readonly<Record<UseCaseKey, DefaultRecord>> = {
  kyc: { g3_choice: "dcipher" },
  kyc_lending: { g3_choice: "dcipher" },
  m_and_a: { g3_choice: "dcipher", multi_oracle_default: true },
  regulated_eu: { g3_choice: "dcipher" },
  evidence: { g3_choice: "dcipher", multi_oracle_default: true },
  testament: {
    g3_choice: "drand",
    pda_updatable: true,
    conditional_recipients_updatable: true,
  },
  time_lock: { g3_choice: "drand" },
  archival: {
    g3_choice: "drand",
    pda_updatable: true,
    conditional_recipients_updatable: true,
  },
  dead_man_switch: {
    g3_choice: "drand",
    pda_updatable: true,
    conditional_recipients_updatable: true,
    multi_oracle_default: true,
  },
  long_retention: {
    g3_choice: "drand",
    pda_updatable: true,
    conditional_recipients_updatable: true,
  },
} as const;

export function normalizeDefaultKey(value: string): string {
  return value.toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
}

export function getUseCaseDefaults(
  use_case: string | undefined,
): DefaultRecord {
  if (use_case === undefined) return {};
  return USE_CASE_DEFAULTS[normalizeDefaultKey(use_case) as UseCaseKey] ?? {};
}
