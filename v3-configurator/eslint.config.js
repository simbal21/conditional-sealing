// ESLint flat-config for @cealis/v3-configurator. Mirrors @cealis/v3-custody pattern.
import tseslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
  {
    files: ["src/**/*.ts", "tests/**/*.ts", "fixtures/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: "./tsconfig.test.json",
        sourceType: "module",
        ecmaVersion: 2022,
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
    },
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/consistent-type-imports": ["error", { prefer: "type-imports" }],
      "@typescript-eslint/no-misused-promises": "error",
      "no-console": ["error", { allow: ["error", "warn"] }],
    },
  },
  {
    // `**/*.d.ts` excluded: declaration files are tsc-generated build artifacts (not
    // source). The `src/**/*.ts` files glob above matches `.d.ts` too, which the typed
    // parser then fails on because `.d.ts` files aren't in tsconfig.test.json's
    // `include`. Mirrors the v3-sd / v3-api ignore pattern.
    ignores: ["dist/**", "coverage/**", "node_modules/**", "**/*.d.ts"],
  },
];
