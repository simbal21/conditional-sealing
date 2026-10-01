import { defineConfig } from "vitest/config";

// Phase A coverage thresholds note:
//   Phase A foundation modules are types-only + signature-only scaffolds
//   consumed by Codex Phases B/C/D/E. The final ≥90% gate per
//   PHASE-PLAN §F.6 is asserted at Phase F closeout after the full
//   commit/Merkle/proof/SDK ship. Phase A coverage is informational.
export default defineConfig({
  test: {
    globals: false,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    exclude: ["sdk/**", "node_modules/**", "dist/**"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "json-summary"],
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.d.ts",
        "src/index.ts",
        "src/m1-imports.ts",
        "src/m2-imports.ts",
        // Phase A type-only / signature-only modules — covered by Phase B/C/D/E.
        "src/types/**",
        "src/tags/preimages.ts",
        "src/commit/construction.ts",
        "src/commit/salt-derivation.ts",
        "src/merkle/tree.ts",
        "src/merkle/binding.ts",
        "src/boundary/types.ts",
        "src/setup/constraint-budgets.ts",
      ],
      thresholds: {
        lines: 0,
        functions: 0,
        branches: 0,
        statements: 0,
      },
    },
  },
});
