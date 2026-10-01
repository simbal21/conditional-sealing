import { defineConfig } from "vitest/config";

// Phase A coverage thresholds note:
//   Phase A foundation modules are types-only + signature-only scaffolds
//   consumed by Codex Phases B/C/D/E. The final ≥90% gate per
//   PHASE-PLAN §F.6 is asserted at Phase F closeout after the full
//   route handlers + bundle assembly + SDK ship.
//
//   For Phase A the coverage report is informational — `pnpm run test`
//   is the load-bearing pass. Codex chunks B/C/D/E SHOULD bump the
//   thresholds when implementation lands.
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
        "src/m2-imports.ts",
        "src/m3-imports.ts",
        "src/m4-imports.ts",
        // Phase A type-only / interface-only modules — covered by
        // Phase B/C/D/E implementation chunks.
        "src/types/**",
        "src/redaction/**",
        "src/openapi/**",
      ],
      // Phase A interim thresholds — Phase F bumps to 90/90/85/90.
      thresholds: {
        lines: 0,
        functions: 0,
        branches: 0,
        statements: 0,
      },
    },
  },
});
