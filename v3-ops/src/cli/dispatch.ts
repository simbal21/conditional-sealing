import type { CeremonyOutcome } from "../ceremony/index.js";

/**
 * Registry mapping CLI slug → ceremony runner. Phase B/C/D ceremony
 * implementations register here; the CLI bin reads this map to dispatch.
 *
 * Each runner accepts the raw CLI rest args and a `dryRun` flag, builds
 * the appropriate ceremony class with input parsed from args (or from
 * stdin / a JSON file), and returns the outcome.
 *
 * Implementations are deliberately thin — they don't parse `--ref 0xdead`
 * style flags themselves. Each runner accepts an `input-file <path>` rest
 * arg containing the JSON payload for the ceremony.
 */
export interface CeremonyRunner {
  readonly slug: string;
  run(args: {
    readonly dryRun: boolean;
    readonly rest: readonly string[];
  }): Promise<CeremonyOutcome>;
}

const REGISTERED = new Map<string, CeremonyRunner>();

export function registerRunner(runner: CeremonyRunner): void {
  REGISTERED.set(runner.slug, runner);
}

export function getRunner(slug: string): CeremonyRunner | undefined {
  return REGISTERED.get(slug);
}

export function listRegistered(): readonly string[] {
  return Array.from(REGISTERED.keys());
}
