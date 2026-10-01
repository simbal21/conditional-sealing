import { defineConfig } from "vitest/config";

// Phase A coverage thresholds note:
//   Phase A ships foundation modules (errors, types, catalog, logging,
//   registry helpers, multisig wrappers, adapter stubs, m2/m3/m4 imports,
//   CLI skeleton). Real coverage gates live at Phase F closeout when
//   ceremony scripts + runbooks + invariant tests are complete.
//
//   At Phase A, the load-bearing assertion is `pnpm run test` green
//   for the 12 foundation tests; coverage is informational.
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
        "src/m2-imports.ts",
        "src/m3-imports.ts",
        "src/m4-imports.ts",
        // Phase A type-only / interface-only / catalog modules — covered
        // by Phase B/C/D/E ceremony implementations.
        "src/types/**",
        "src/catalog/**",
        "src/adapters/**",
        "src/cli/**",
      ],
      // Phase A interim thresholds — Phase F bumps to 85/85/80/85.
      thresholds: {
        lines: 0,
        functions: 0,
        branches: 0,
        statements: 0,
      },
    },
  },
});
