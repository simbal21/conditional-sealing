> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# TS-API ingest + configurator-PDA backlog reconciliation — HEAD e87c108 (2026-06-02)

Read-only audit. Verdicts derived from actual code at HEAD via grep/read (Rule 45).

## Cross-cutting context that shapes several verdicts

1. **The ingest route is NOT mounted to any production server.** `registerIngestRoutes` /
   `registerCreateModeAIngestionRoute` are called only from `v3-api/tests/integration/*`.
   The single `Fastify(...)` call in production code is `server/index.ts:90`
   (`Fastify(deps.fastifyOptions ?? { logger: false })`), and `createFastifyApp` there does
   NOT register ingest routes. This is Stage-3 build code, not a deployed API.
2. **No runtime schema validation is wired in v3-api at all.** grep for
   `TypeBoxTypeProvider | setValidatorCompiler | withTypeProvider | ajv | Value.Check | preValidation`
   across `v3-api/src` returns ZERO hits. TypeBox schemas in the ingest module are
   used only for OpenAPI doc generation via `RouteRegistry` (a `Map<operationId, descriptor>` — see
   `openapi/scaffold.ts`). `RouteRegistry.register()` never attaches a schema to a Fastify route.
3. **The ingest `app.post("/v1/ingestions", handler)` at routes-create-mode-a.ts:655 passes NO
   `schema` option.** Contrast with the shred routes (partner/subject), which DO pass
   `{ schema: { params: {...} } }` to `app.post` — those validate at runtime; the ingest route does not.

---

## TS-API-F-01 — ingestion schema additionalProperties:true accepts unbounded plaintext_payload

**Status: PARTIAL** · severity MEDIUM (was the original framing's concern)

- `ModeAIngestionRequestSchema` now declares `{ additionalProperties: false }` at
  routes-create-mode-a.ts:168 (root object). `plaintext_payload: Type.Unknown()` at :155.
- The "unbounded payload" concern: the comment at :167 claims size is bounded by
  "Fastify bodyLimit (see server.ts bodyLimit)". There is NO `server.ts` and NO explicit
  `bodyLimit` anywhere in v3-api (grep `bodyLimit` → only the comment). HOWEVER Fastify's
  DEFAULT bodyLimit (1 MiB) applies at the raw-body parse layer regardless of schema, so the
  payload IS de-facto bounded to ~1 MiB when the route is eventually mounted. The
  unbounded-payload risk is mitigated by the framework default, NOT by anything in this code.
- The `additionalProperties: false` half of the fix does NOT execute (see cross-cutting #2/#3):
  no validator compiler, no `schema` on the route. So the schema-level rejection is cosmetic.
- Net: payload-size bound = real (framework default, not code); schema enforcement = not wired.
  Partial because the protection the comment claims (schema validator) is absent; the actual
  protection (1 MiB default) is incidental and the comment misattributes it.

## TS-API-F-02 — h_commit URL param not format-validated in shred routes

**Status: FIXED** · severity LOW/MEDIUM

- Partner route: `partner/routes-create-shred-request.ts:54-62` attaches
  `schema: { params: { type:"object", required:["h_commit"], properties:{ h_commit:{ type:"string",
  pattern: "^0x[0-9a-fA-F]{64}$" } } } }` to the real `app.post(..., {schema}, handler)`.
- Subject route: `subject/routes-create-shred-request.ts:48-55` — identical params schema.
- These ARE attached to the Fastify route's `schema` option (unlike ingest), so Fastify validates
  the URL param at runtime and rejects malformed `h_commit` (400) before the handler/DB lookup.
- `HCOMMIT_HEX_PATTERN = "^0x[0-9a-fA-F]{64}$"` (partner :10, subject :7). Both files cite
  TS-API-F-02 in comments. Fix is genuine and runtime-effective.

## TS-API-F-04 — root ingestion schema accepts unknown top-level keys

**Status: PARTIAL** · severity LOW/MEDIUM

- `ModeAIngestionRequestSchema` root object now has `{ additionalProperties: false }` at :168,
  with a comment (:163-168) explicitly tagging TS-API-F-01/F-04.
- BUT, per cross-cutting #2/#3, this schema is never enforced at runtime: the `app.post` route
  has no `schema`, and no TypeBox→ajv validator compiler is configured. So unknown top-level keys
  are NOT rejected by the validator. They are instead silently ignored by the handler, which does
  explicit field-by-field extraction (`body.pda_id`, `ensureHex32(...)`, `recordDigest(...)`),
  so there is no prototype-pollution / smuggle path from extra TOP-LEVEL keys today — but the
  declared defense (schema rejection) does not run. The fix is declared, not executed.
- Partial: the schema text closes the gap on paper; the value is realized only once the route is
  mounted AND a validator compiler is wired (neither is true at HEAD).

## TS-API-F-05 — Stage-3 PDA validation structurally a no-op (synthetic↔synthetic)

**Status: OPEN** · severity HIGH

- `validatePDA` → `validateStage3Pda(adaptToStage3(submitted), buildStage3Context(submitted))`
  at emit.ts:162.
- `adaptToStage3(_submitted)` (emit.ts:356-366): the `_submitted` param is underscore-prefixed and
  UNUSED. Surfaces are built entirely from `CLASS_TABLE_ROWS` with hardcoded synthetic values:
  PDA-pick rows → `allowed:${row.id}`, parameter rows → `5`, else → `n/a:${row.id}`.
- `buildStage3Context(_submitted)` (emit.ts:327-354): `_submitted` also UNUSED. allowLists →
  `[allowed:${row.id}]`, bounds → `{min:0,max:10}`, registryEntries → live entries for every row.
  The context is purpose-built so the synthetic surfaces from `adaptToStage3` ALWAYS pass.
- The Stage-3 validators themselves (`validate/stage3/*.ts`, index.ts:88-93) are real and functional,
  but no partner-supplied class-table value (PDA pick / parameter / registry ref / template-id) ever
  reaches them — they validate a fixture against a fixture. Real PDA content is never class-table-checked.
- Unchanged from the original finding. Structural no-op confirmed at HEAD.
- Fix location: emit.ts `adaptToStage3` + `buildStage3Context` must derive the Stage-3 surfaces AND
  the allow-list/bounds/registry context from the real `submitted` PDA (class-table-driven extraction
  of submitted field values + a context sourced from the real registry/class-table state), not from
  hardcoded `CLASS_TABLE_ROWS` synthetics.

## TS-API-F-08 — prepareSubmittedPda fills defaults bypassing required-field check

**Status: PARTIAL** · severity MEDIUM/HIGH

- The vulnerable defaulting in `prepareSubmittedPda` is UNCHANGED and live:
  - emit.ts:260 `partner_id: String(scaffold.partner_id ?? "partner_fixture")` — missing partner_id
    becomes the synthetic fixture (the exact attribution-forgery the finding names).
  - emit.ts:248 `pda_id` derived from `${partner_id ?? "partner"}:${templateName}` when absent.
  - emit.ts:316 `retention_seconds ?? 31_536_000`; :247 template_id seeded; etc.
- A NEW guard primitive was added: `PARTNER_SUPPLIED_REQUIRED_FIELDS` (emit.ts:206-212, freezes
  partner_id/pda_id/pda_version/template_id/retention_seconds), `PartnerInputMissingRequiredFieldsError`
  (:214-224, code `MISSING_REQUIRED_FIELD`), and `assertPartnerInputRequiredFields(input)` (:226-237).
  Its docstring (:197-204) says "Use this at every API-boundary call-site ... before invoking
  prepareSubmittedPda."
- BUT `assertPartnerInputRequiredFields` has ZERO callers anywhere in the repo. grep for it
  (excluding /dist/) returns ONLY its own definition. It is NOT called from `prepareSubmittedPda`,
  `validatePDA`, `emitPDA`, the CLI (`cli/validate.ts` calls `validatePDA(JSON.parse(...))` raw),
  or any API boundary. The guard is dead code.
- Net: a remediation helper exists but is unwired; the defaulting that forges attribution is still
  reachable through `validatePDA` / `emitPDA` / the CLI on partner input. Partial.
- Fix location: call `assertPartnerInputRequiredFields(input)` at the head of every real
  partner-facing boundary (the configurator API ingest path + `cli/validate.ts` when not a fixture),
  OR enforce it inside `validatePDA`/`emitPDA` with an opt-out flag for the internal fixture/test
  generators that legitimately rely on defaults.
