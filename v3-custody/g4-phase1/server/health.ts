export interface HealthResult {
  readonly status: "ok";
  readonly phase: 1;
  readonly detail: string;
}

export function health(): HealthResult {
  return {
    status: "ok",
    phase: 1,
    detail: "G4 Phase 1 daemon ready",
  };
}
