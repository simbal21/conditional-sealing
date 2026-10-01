// @cealis/v3-demo/m6-sdk-imports — typed re-export facade for
// @cealis/v3-sd-verify (partner-side SD verification SDK, S2-7 §9).
//
// Independence is normative — this package MUST NOT have any workspace
// dependency on @cealis/v3-api or @cealis/v3-custody at runtime. We
// re-export here so Round 3 verification code consumes both M6 facades
// via demo-package imports, not via cross-workspace coupling.

export * from "@cealis/v3-sd-verify";
