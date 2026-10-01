import {
  REFUSAL_CODE_COUNT,
  REFUSAL_CODES,
  isAdvisory,
  isBlocking,
  isEncryptedReasonMode,
  validateAdvisory,
  validateBlocking,
} from "../refusal/codes.js";
import { RefusalCode, type RefusalCodeValue } from "../types/refusal.js";

export {
  REFUSAL_CODE_COUNT,
  REFUSAL_CODES,
  RefusalCode,
  isAdvisory,
  isBlocking,
  isEncryptedReasonMode,
  validateAdvisory,
  validateBlocking,
};

export function assertRefusalEnumMatchesM2(): void {
  if (REFUSAL_CODE_COUNT !== 10) {
    throw new Error(`G4 refusal enum drift: expected 10 codes, got ${REFUSAL_CODE_COUNT}`);
  }
  for (let code = RefusalCode.LegalCompel; code <= RefusalCode.OracleDeprecated; code++) {
    validateBlocking(code);
  }
  validateAdvisory(RefusalCode.OptOutActive);
}

export function isKnownRefusalCode(code: number): code is RefusalCodeValue {
  return Object.values(RefusalCode).includes(code as RefusalCodeValue);
}

export function refusalCodeHex(code: number): string {
  return `0x${code.toString(16).padStart(2, "0").toUpperCase()}`;
}
