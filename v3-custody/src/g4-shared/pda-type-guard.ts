import type { Hex32 } from "@cealis/v3-crypto";
import { CustodyError, CUSTODY_ERROR_CODES } from "../errors.js";

export const G4Phase = {
  Phase1: 1,
  Phase2: 2,
} as const;

export type G4Phase = (typeof G4Phase)[keyof typeof G4Phase];

export const PdaTypeClass = {
  DevScaffold: "dev-scaffold",
  PartnerReady: "partner-ready",
  LegalEffect: "legal-effect",
} as const;

export type PdaTypeClass = (typeof PdaTypeClass)[keyof typeof PdaTypeClass];

const LEGAL_EFFECT_TYPES = new Set([
  "kyc-lending",
  "m-and-a",
  "evidence",
  "medical",
  "testament",
  "financial-records-audit",
]);

const PARTNER_READY_TYPES = new Set([
  "partner-ready",
  "partner-pilot",
  "production-partner",
]);

export interface PdaEligibilityInput {
  readonly phase: G4Phase | number;
  readonly pdaType?: string;
  readonly pdaClass?: PdaTypeClass;
  readonly legalEffectExpected?: boolean;
  readonly partnerReady?: boolean;
  readonly pdaRoot?: Hex32;
  readonly commitAAD?: Readonly<{
    phase?: number;
    pdaType?: string;
    pda_class?: string;
    legalEffectExpected?: boolean;
    legal_effect_expected?: boolean;
    partnerReady?: boolean;
    partner_ready?: boolean;
  }>;
}

export interface PdaEligibilityDecision {
  readonly ok: boolean;
  readonly phase: number;
  readonly pdaClass: PdaTypeClass;
  readonly code?: typeof CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE;
  readonly reason: string;
}

export function classifyPdaType(input: PdaEligibilityInput): PdaTypeClass {
  if (input.pdaClass !== undefined) return input.pdaClass;

  const explicitClass = input.commitAAD?.pda_class;
  if (explicitClass === PdaTypeClass.DevScaffold) return PdaTypeClass.DevScaffold;
  if (explicitClass === PdaTypeClass.PartnerReady) return PdaTypeClass.PartnerReady;
  if (explicitClass === PdaTypeClass.LegalEffect) return PdaTypeClass.LegalEffect;

  const legal =
    input.legalEffectExpected === true ||
    input.commitAAD?.legalEffectExpected === true ||
    input.commitAAD?.legal_effect_expected === true;
  if (legal) return PdaTypeClass.LegalEffect;

  const partner =
    input.partnerReady === true ||
    input.commitAAD?.partnerReady === true ||
    input.commitAAD?.partner_ready === true;
  if (partner) return PdaTypeClass.PartnerReady;

  const rawType = normalizeType(input.pdaType ?? input.commitAAD?.pdaType);
  if (rawType !== undefined) {
    if (LEGAL_EFFECT_TYPES.has(rawType)) return PdaTypeClass.LegalEffect;
    if (PARTNER_READY_TYPES.has(rawType)) return PdaTypeClass.PartnerReady;
  }

  return PdaTypeClass.DevScaffold;
}

export function checkG4PhaseEligibility(input: PdaEligibilityInput): PdaEligibilityDecision {
  const phase = input.commitAAD?.phase ?? input.phase;
  const pdaClass = classifyPdaType(input);
  if (phase === G4Phase.Phase1 && pdaClass !== PdaTypeClass.DevScaffold) {
    return {
      ok: false,
      phase,
      pdaClass,
      code: CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE,
      reason: "G4 Phase 1 is dev-scaffold only; partner-ready and legal-effect PDAs require Phase 2",
    };
  }
  if (phase !== G4Phase.Phase1 && phase !== G4Phase.Phase2) {
    return {
      ok: false,
      phase,
      pdaClass,
      code: CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE,
      reason: `Unsupported G4 phase ${phase}`,
    };
  }
  return {
    ok: true,
    phase,
    pdaClass,
    reason: "G4 phase eligible for PDA class",
  };
}

export function assertG4PhaseEligible(input: PdaEligibilityInput): PdaEligibilityDecision {
  const decision = checkG4PhaseEligibility(input);
  if (!decision.ok) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE,
      decision.reason,
      {
        metadata: {
          phase: decision.phase,
          pdaClass: decision.pdaClass,
        },
      },
    );
  }
  return decision;
}

function normalizeType(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.trim().toLowerCase().replaceAll("_", "-");
}
