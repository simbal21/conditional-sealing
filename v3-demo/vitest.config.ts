import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Phase A foundation tests are type-shape + import-smoke + discipline tests.
// They do NOT require infra (Postgres/Redis/Anvil) to run.
// Coverage thresholds are informational at Phase A; round implementations
// in Phase B/C/D/E provide the real coverage surface.
//
// Alias map for @cealis/v3-configurator/fixtures: upstream package.json
// declares this subpath export, but the upstream build's tsconfig excludes
// the fixtures dir from compilation — so dist/fixtures/app-a/ doesn't exist.
// See the internal integration-gap log. We resolve to the upstream source at
// runtime via this alias; build-time resolution uses tsconfig paths.
export default defineConfig({
  resolve: {
    alias: {
      "@cealis/v3-configurator/fixtures": fileURLToPath(
        new URL("../v3-configurator/fixtures/app-a/index.ts", import.meta.url),
      ),
    },
  },
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
        "src/m5-imports.ts",
        "src/m6-imports.ts",
        "src/m7-imports.ts",
        "src/cli.ts",
        "src/rounds/**",
        "src/cross-round/**",
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
