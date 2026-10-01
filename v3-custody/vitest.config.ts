import { defineConfig } from "vitest/config";

// Coverage thresholds note:
//   Phase A foundation files include types-only modules + chain reader
//   that are exercised only by Phase B/C/D/E adapters/combiner. The
//   final ≥95% gate per PHASE-PLAN §F.5 is asserted at Phase F closeout
//   after the full SDK is built.
//
//   For Phase A the coverage report is informational — `pnpm run test`
//   is the load-bearing pass. Per PHASE-PLAN: "coverage report —
//   combiner ≥95%, adapters ≥95%, Phase 2 deferred surface tolerated
//   lower (interface conformance only)".
//
//   Codex chunks B/C/D/E SHOULD bump the thresholds when their adapter
//   code lands.
export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "json-summary"],
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.d.ts",
        "src/index.ts",
        "src/m1-imports.ts",
        // Phase A type-only / interface-only modules — covered by
        // Phase B/C/D/E adapter implementations.
        "src/types/**",
        "src/adapters/**",
        "src/chain/**",
        "src/access-structure/**",
      ],
      // Phase A interim thresholds — Phase F bumps to 95/95/90/95.
      thresholds: {
        lines: 95,
        functions: 95,
        branches: 85,
        statements: 95,
      },
    },
  },
});
