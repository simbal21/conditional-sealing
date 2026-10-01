import { CustodyError, CUSTODY_ERROR_CODES } from "../errors.js";
import {
  G4Phase,
  checkG4PhaseEligibility,
  type PdaEligibilityInput,
} from "../g4-shared/pda-type-guard.js";

export function assertG4Phase2Eligible(input: Omit<PdaEligibilityInput, "phase"> & { readonly phase?: number }): void {
  const phase = input.phase ?? G4Phase.Phase2;
  if (phase !== G4Phase.Phase2) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
      "G4 Phase 2 adapter rejects Phase 1 commits",
    );
  }
  const decision = checkG4PhaseEligibility({ ...input, phase });
  if (!decision.ok) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE,
      decision.reason,
    );
  }
}
