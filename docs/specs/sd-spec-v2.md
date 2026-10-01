# Cealis V2 System, V3 Custody - Selective Disclosure Specification (S2-7)

## §0 - Front Matter

### §0.1 Document identity

**Title:** Cealis V2 System, V3 Custody - Selective Disclosure Specification (S2-7)

**Stage:** Stage-2 mandatory specification. S2-7 is the normative selective-disclosure specification for the V2 system with V3 custody architecture. It defines the parallel selective-disclosure pipeline that runs at commit time inside the Mode A ingestion TEE boundary, emits cleartext fields and zero-knowledge proofs to the partner at onboarding, and remains isolated from the escrow release path. It consumes S2-1 for escrow cryptographic conventions and S2-2 for contract-surface boundaries, but S2-7 is canonical for SD-side commitments, SD tag namespace, Poseidon Merkle construction, PLONK circuit surfaces, partner verification, proof expiry, revocation, and test obligations.

**Output artifact:** this markdown document only. S2-7 does not implement circuits, witness generators, verifier contracts, SDK packages, REST endpoints, or Solidity code. Stage 3 implements this specification and proves conformance through circuit test vectors, witness-generation tests, verifier tests, partner-SDK tests, and end-to-end Mode A onboarding tests.

**Full-refresh status:** this is a fresh V2-system, V3-custody SD specification. It is not a delta document against any earlier selective-disclosure material. The SD pipeline is mandatory Stage-2 scope under Stage-0 Q-0-7 and full-engine scope under Stage-0 §0. Every predicate type, field-mapping mode, verification surface, revocation layer, and Mode B rejection rule named here is in-scope for the full engine.

**Version semantics:** this document's own version is `1.0-draft`. The escrow protocol version it consumes is S2-1 `commit_version = 0x0302`. SD tags carry `_V3` because they belong to the V3-custody refresh of the SD pipeline, but they use the disjoint `CEALIS_SD_` namespace rather than S2-1's `CEALIS_V3_` escrow namespace.

### §0.2 Audience and reading order

**Cealis-internal SD engineer.** Read §1 conventions, §2 topology, §3 tag family, §4 per-field commitments, §5 Merkle-root construction, §6 predicates, §7 circuits, §8 onboarding delivery, §11 revocation, §13 shredding, §14 Mode B incompatibility, §15 isolation, and §16 tests. App. A is the implementation checklist for circuit shape and public-signal ordering.

**Partner-side SD integrator.** Read §0.9 PII content statement, §8 onboarding payload, §9 partner verification SDK, §11 revocation checks, §12 field mapping, §13 shredding consequences, and App. B test-vector categories. The partner integrator does not need to implement the TEE-side generator, but must verify every received cleartext field and proof before treating an onboarding response as valid.

**External auditor.** Read §0.6 source ordering, §0.7 discipline anchors, §1 error and logging conventions, §2 two-pipeline topology, §4 commitment construction, §5 root binding and escalation, §6 Claim binding, §7 PLONK constraints, §10 on-chain verifier shape, §11 revocation, §14 Mode B incompatibility, §15 asymmetric isolation, §16 tests, §17 cross-references, and App. C scope-outs. The audit question is narrow: can SD leak escrowed plaintext, bypass the predefined on-chain release condition, block escrow commit success, store salts, create post-commit proof generation, or let stale proofs pass after expiry/revocation?

### §0.3 Terminology discipline

**V2 vs V3.** V2 is the system version. V3 is the custody/key-holding subsystem inside V2. This document says "V2 system, V3 custody" or "V3-custody refresh" and does not use bare "V3" as a system-version label.

**SD vs escrow.** The escrow pipeline encrypts the full committed payload into the age envelope and keeps it sealed until the on-chain predefined condition fires and the V3-custody gate tuple is available. The SD pipeline emits partner-approved cleartext fields and proofs at commit time. SD output is not a reveal, not a partial reveal, not an extraction from escrow, and not a fallback decryption path.

**Field mapping.** Each schema field in a PDA has exactly one SD policy state for a given partner onboarding response: `cleartext`, `zkp`, or `escrow_only`. `cleartext` means the partner receives the field value at onboarding and can verify it against an SD commitment. `zkp` means the partner receives a proof of configured predicates over the field without receiving the field value. `escrow_only` means the field participates only in escrow and is not exposed through SD output.

**Predicate types.** S2-7 ships four predicate families: range, equality, set membership, and non-equality. They compose into partner-defined Claims using bounded `AND`, `OR`, and `NOT`. SD Claims are not the same as ConditionEngine Claims: ConditionEngine Claims decide reveal/shred ceremonies on-chain; SD Claims prove onboarding-time statements about plaintext fields inside the TEE.

**Proof objects.** SD PLONK proofs are partner-consumable verification artifacts. They are not custody σ values and are not HKDF input keying material. They may be public or partner-held depending on delivery policy, but proof public inputs may still contain PII-adjacent values such as `partner_id`, `pda_id`, field ids, expiry timestamps, and `authorizationId`.

### §0.4 What this spec does not cover

S2-7 does not specify the V3-custody escrow envelope, gate signatures, `file_key` derivation, AEAD payload, or combiner protocol. Those are S2-1.

S2-7 does not specify ConditionEngine module logic, custody registries, ShredRegistry mechanics, PasskeyRotationLog, G4RefusalRegistry, or general access-control role surfaces except where SD needs an isolated registry/verifier shape. Those are S2-2.

S2-7 does not specify the full PDA configurator UI, CLI/API, template library, schema editor, simulation UI, or validation copy. It specifies the normative SD field-mapping model and validation rules that S2-4 must implement.

S2-7 does not specify HTTP transport, endpoint names, idempotency keys, webhook semantics, or partner onboarding-response JSON wire details beyond the payload fields needed for SD verification. Those live in S2-5.

S2-7 does not specify TEE vendor SDK pins, PLONK library pins, Poseidon implementation versions, proving-key custody ceremonies, trusted-setup artifacts, verifier deployment ceremonies, or operational alert runbooks. Those live in S2-3 and S2-6.

### §0.5 Status of this document

S2-7 is implementation-grade prose, pre-Stage-3. It is normative about data model, field order, public-signal order, tag labels, error semantics, isolation rules, and verification obligations. Stage 3 will produce byte-exact test vectors for Poseidon, Merkle roots, proof public inputs, verifier calldata, and SDK return types.

The 2026-05-05 backprop cycle closed S2-7's explicit cross-spec escalation: S2-1 now scopes SD tags to S2-7 and carries `sdMerkleRoot` in `CommitAAD`. The 2026-05-06 IB-4 backprop closes the SD salt-cycle issue: salts derive from a pre-root `sd_salt_context_digest`, not any final-commit or zero-placeholder value. S2-7 remains canonical for SD root construction and proof semantics; S2-1 remains canonical for the escrow byte layout that binds the root.

### §0.6 Source-of-truth ordering

For byte-exact V3 escrow constructions, S2-1 is canonical. S2-7 imports S2-1 conventions where explicitly named, especially domain-separation discipline, SCALE-vs-byte-concat discipline, `authorizationId`, final `h_commit`, `pda_root`, `commit_AAD`, HKDF convention for SD salts, and Shamir `file_key` reconstruction as an isolation boundary.

For on-chain contract shape, role model, registry governance, UUPS discipline, and SD/escrow isolation at contract level, S2-2 is canonical. S2-7 consumes S2-2's rule that escrow contracts do not parse SD plaintext or proofs except through S2-7-defined verifier surfaces, and that SD verifier state cannot affect escrow reveal authorization.

For full-engine scope, Stage-0 decisions are binding: SD is mandatory, Mode A and Mode B both exist at the engine level, Mode B is SD-incompatible, and all full-surface field mappings and predicate types ship.

For project framing, WP §B P5, §G, §H, §K, and §P are canonical within the corpus: SD is a parallel pipeline, Mode A is the plaintext-TEE boundary that makes it possible, Mode B cannot run TEE-side SD, and public copy must not imply that SD is a reveal path.

Within the Stage-2 stack, S2-7 is canonical for SD. Downstream implementation may not invent alternate tag labels, field encodings, public-signal order, predicate semantics, revocation semantics, or Mode B fallbacks.

### §0.7 Document discipline anchors

**Rule 3 - two parallel pipelines, never crossing.** SD runs alongside escrow at commit. It shares the escrow DEK only as one-way HKDF input to derive SD salts. SD never receives gate signatures, never derives `file_key`, never decrypts the escrow envelope, and never emits escrow plaintext after commit.

**Rule 6b - onboarding-only SD.** SD outputs are generated only at onboarding/commit time. Plaintext is destroyed after TEE processing. No post-onboarding proof generation is supported. Salts are ephemeral TEE-only and never stored in vault, logs, partner payloads, or chain state.

**Rule 12 - production-grade surface.** Every normative field, error, and verification step here is intended for direct implementation. Scope-outs are explicit and routed to named Stage-2 sibling specs. There are no hidden placeholders inside normative scope.

**Rule 26 - seven-view check.** This spec has been checked against Enforcement, Tamper-proof, SD, Commercial, Legal, Use-case flex, and Partner-fit. Concrete consequence: SD is strong enough for partner onboarding utility, but it cannot collapse the escrow release condition, rewrite the legal reveal artifact, or force every partner into the same disclosure template.

**Rule 29 - V2/V3 naming.** SD is part of the V2 system and is refreshed for V3 custody. Do not call this a "V3 product" or "V3 system".

**Rule 31 - full engine.** All three field-mapping states and all four predicate types ship. There is no pilot subset.

**Universal tripwire.** No release path exists that bypasses the on-chain-verified predefined condition. SD passes because it produces preconfigured onboarding artifacts while plaintext exists at commit time; it does not release escrowed plaintext.

**Crypto-shredding.** DEK destruction makes SD salts unrecoverable, so retroactive proof generation is impossible. Pre-existing partner-held proofs remain cryptographically verifiable unless their expiry or revocation layer rejects them.

**Mode B incompatibility.** Mode B has no TEE plaintext at commit and therefore cannot run this TEE-side SD pipeline. Configurator and ingestion APIs must reject any PDA configuration that combines Mode B with SD.

### §0.8 Cross-reference index

Imported from S2-1:

| S2-1 anchor | S2-7 use |
|---|---|
| §1 conventions | hash, HKDF, SCALE, endian, fail-closed, no SDK version pins |
| §2 tag registry | tag construction discipline and disjoint SD namespace obligation |
| §3 composite identifiers | `authorizationId`, `h_commit`, `pda_root` binding into SD contexts |
| §4 `commit_AAD` | `commit_version = 0x0302` binding point for `sdMerkleRoot` |
| §1.1 HKDF | one-way SD salt derivation from DEK uses HKDF-SHA256 convention with distinct tag/info |
| §6.3 Shamir reconstruction | isolation boundary: SD state never participates in `file_key` reconstruction |
| §10 Mode 3 | not directly consumed by SD; cited only to avoid confusing conditional-recipient proofs with SD proofs |
| §16 error model | SD-specific error layer inherits no PII/no salt/no plaintext logging |
| §17 and App. C | SD is S2-7-owned and disjoint from escrow crypto |

Imported from S2-2:

| S2-2 anchor | S2-7 use |
|---|---|
| §0.4 | S2-2 leaves SD circuits and registry detail to S2-7 |
| §1.3 custom errors | no PII, σ, plaintext, partial AAD, or salt in error arguments |
| §1.5 and §16 | role naming and Timelock/registry governance discipline for SD contracts |
| §9 common registry shape | historical lookup, deprecation, disclosure, tombstone model inherited where applicable |
| App. A `IDisclosureRegistry` | minimal prior shape consumed and expanded by S2-7 |
| §21.6/§21.16 | SD state cannot affect escrow reveal authorization |

Downstream consumption:

| Downstream spec | S2-7 surface consumed |
|---|---|
| S2-3 | Poseidon, PLONK, trusted setup, proving system and SDK library pins |
| S2-4 | `cleartext/zkp/escrow_only` field mapping, Mode B rejection, predicate config validation |
| S2-5 | onboarding response payload, partner delivery, error transport, proof expiry return semantics |
| S2-6 | proving key ceremony, verifier deployment ceremony, revocation operations, alerting |
| Stage 3 | circuits, verifier contracts, SDK, test vectors, conformance report |

### §0.9 PII content statement

SD outputs may contain PII. A `cleartext` field is plaintext by definition. A `zkp` proof may avoid revealing the witness field value, but its public inputs can still disclose facts about the subject: a range bound, set identifier, partner id, field id, claim id, expiry timestamp, revocation id, or a binary predicate result. S2-7 therefore treats the entire SD output bundle as partner-confidential unless the PDA explicitly marks a Claim as public-verifiable.

SD commitments are not plaintext, but they are derived from plaintext field values and per-field salts. They are pseudonymous cryptographic artifacts and must be handled as confidential partner onboarding records. SD salts are never disclosed or stored. SD logs must not contain field values, salts, witness values, proof internals, or malformed witness dumps.

## §1 - Conventions

### §1.1 Field-mapping conventions

Every PDA schema field addressed by SD has a canonical `field_id`. `field_id` is a 32-byte value:

```
field_id = keccak256(
  TAG_SD_FIELD_ID_V3
  || schema_digest
  || field_path_hash
  || field_type_code
)
```

`field_path_hash` is `keccak256(utf8(normalized_field_path))`. Field paths use dot-separated canonical schema paths with array positions represented by the literal segment `[]` for homogeneous array fields. `field_type_code` is one byte for the canonical type family: `0x01 string`, `0x02 uint`, `0x03 int`, `0x04 bool`, `0x05 bytes`, `0x06 date`, `0x07 decimal_fixed`, `0x08 enum`, `0x09 country_code`, `0x0A address`, `0x0B object_hash`.

For each `(pda_id, pda_version, partner_id, field_id)`, the PDA field mapping assigns one of:

| State | Meaning | Partner receives |
|---|---|---|
| `cleartext` | field value is disclosed at onboarding | canonical value, field commitment opening data excluding salt, field commitment, Merkle path |
| `zkp` | field value remains undisclosed but predicates are proven | proof, public inputs, field commitment, Merkle path |
| `escrow_only` | field is not part of SD output | no field value, no proof, no Merkle path unless needed as non-disclosed tree placeholder in a full audit bundle |

The default is `escrow_only`. Any `cleartext` or `zkp` setting must be explicit in the PDA configuration. Configurator output must be deterministic: two configurator clients given the same PDA schema and field mapping emit the same ordered SD plan.

### §1.2 Encoding conventions

**Hash split.** Escrow uses keccak-256 per S2-1. SD uses Poseidon over the BN254 scalar field for field commitments and Merkle trees because these values are verified inside PLONK circuits. Keccak remains used for tag constants, field-id derivations, claim ids, and EVM-facing digest refs where the value is not recomputed inside a circuit.

**BN254 field.** All circuit-level scalars live in the BN254 scalar field:

```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

Any byte string interpreted as a scalar must be less than `p`. If a digest is naturally 32 bytes and may exceed `p`, it is reduced through the circuit's canonical hash-to-field function:

```
scalar = OS2IP(bytes32_value) mod p
```

Reduction is allowed only for domain-separated digest-to-field conversion sites named in this spec. Raw reduction of user values is forbidden where it would create semantic collisions. User values use type-specific encodings in §4.2.

**Byte order.** EVM-facing integer encodings use S2-1/S2-2 conventions at the named surface. Circuit witness encodings use unsigned big-endian byte strings before conversion to field elements unless a type-specific rule states otherwise. Public inputs emitted to Solidity verifier contracts are `uint256` values required to be `< p`.

**SCALE.** Structured SD bundles that are hashed outside the circuit use SCALE where variable-length fields appear, matching S2-1's boundary-malleability discipline. Fixed-width circuit public inputs use positional arrays, not SCALE, because Solidity PLONK verifier calldata expects fixed public-signal order.

### §1.3 Error model

S2-7 defines an SD-specific `ERR_SD_*` layer. These errors are fail-closed for the SD artifact being verified, but do not fail escrow commit or escrow reveal unless the caller explicitly configured a business-level onboarding policy outside the escrow pipeline.

Error contexts must not include PII, salts, witness values, malformed plaintext, raw proof bytes, partial AAD bytes, or σ values. Hashes, ids, enum values, timestamps, and proof lengths are acceptable. The canonical top-level errors are:

| Error | Trigger |
|---|---|
| `ERR_SD_CONFIG_MODE_B_INCOMPATIBLE` | PDA enables SD under Mode B |
| `ERR_SD_FIELD_POLICY_UNKNOWN` | field mapping has no valid state |
| `ERR_SD_FIELD_ENCODING_INVALID` | field value cannot be encoded canonically |
| `ERR_SD_SALT_DERIVATION_FAIL` | HKDF failed or returned wrong length |
| `ERR_SD_SALT_ESCAPED_TEE` | implementation attempted to store/log/export an SD salt |
| `ERR_SD_COMMITMENT_MISMATCH` | disclosed field does not match commitment |
| `ERR_SD_MERKLE_PATH_INVALID` | Merkle proof does not lead to expected root |
| `ERR_SD_ROOT_BINDING_MISSING` | expected escrow binding of SD root is absent |
| `ERR_SD_PROOF_INVALID` | PLONK verifier rejects proof |
| `ERR_SD_PUBLIC_INPUT_MISMATCH` | proof public inputs do not match Claim bundle |
| `ERR_SD_CLAIM_EXPIRED` | proof expiry timestamp has passed |
| `ERR_SD_CLAIM_REVOKED` | revocation registry marks claim/disclosure revoked |
| `ERR_SD_PARTNER_MISMATCH` | proof/bundle bound to another partner |
| `ERR_SD_PDA_MISMATCH` | proof/bundle bound to another PDA |
| `ERR_SD_AUTHORIZATION_MISMATCH` | proof/bundle bound to another authorization |
| `ERR_SD_ONBOARDING_PARTIAL_FAILURE` | SD failed while escrow pipeline continued |

### §1.4 Logging discipline

SD logs are operational only. Allowed fields: correlation id, `authorizationId`, `h_commit`, `pda_id`, `partner_id`, `claim_id`, `field_id`, circuit id, verifier ref, proof length, stage name, error code, and monotonic timing. Forbidden fields: plaintext values, cleartext payloads, salts, witness assignments, proving key material, raw proof transcript, malformed input bodies, and generated partner output bodies.

Every log line emitted inside the TEE boundary must pass through the same redaction layer used by G4 ingestion logs. Debug mode may increase stage granularity but may not weaken redaction. A developer needing witness debugging must use synthetic fixtures outside live ingestion, never production subject data.

### §1.5 Asymmetric isolation discipline

The escrow commit pipeline is primary. The SD pipeline is a side pipeline. If escrow encryption succeeds and SD proof generation fails, the commit can still complete as an escrow-only commit unless the partner's commercial onboarding API rejects the onboarding response at the application layer. That rejection is a partner/business retry, not an escrow cryptographic failure.

The one permitted cryptographic dependency from escrow to SD is:

```
DEK -> HKDF-SHA256 -> sd_master_salt -> sd_field_salt_i
```

The arrow is one-way. SD never feeds salts, commitments, proofs, or field mappings back into DEK derivation. SD state never influences `RevealAuthorized`, gate signing, Shamir `file_key` reconstruction, AEAD decryption, G4 refusal, or ShredRegistry state.

## §2 - SD pipeline architecture

### §2.1 Parallel-pipeline topology

Mode A commit receives plaintext inside the Cealis ingestion TEE boundary. From that one plaintext availability window, two independent products are made:

1. The escrow pipeline encrypts the full payload into the age envelope and produces the V3-custody commitment surfaces governed by S2-1 and S2-2.
2. The SD pipeline canonicalizes selected fields, derives ephemeral salts, creates per-field Poseidon commitments, builds an SD Merkle tree, generates configured PLONK proofs, and delivers cleartext/proof artifacts to the partner in the onboarding response.

The SD pipeline does not read from the age envelope and does not write into the age envelope. It reads the same plaintext object while plaintext exists inside the TEE. The sequence is "shared input, separate outputs", not "escrow first, SD extract later".

### §2.2 TEE boundary co-location

For partner-ready V2 deployments under Stage-0 Q-0-2, SD runs in the same Phase 2 G4 TEE boundary as ingestion. This is the conforming S2-7 path:

```
partner/subject upload -> G4 Phase 2 ingestion TEE
  -> schema validation
  -> escrow envelope construction
  -> SD field plan execution
  -> plaintext zeroization
  -> onboarding response
```

Co-location has one important boundary: SD proving code is logically separated from escrow code inside the TEE. A fault in the SD proving module must return `ERR_SD_ONBOARDING_PARTIAL_FAILURE`, zeroize SD witnesses and salts, and allow escrow commit finalization to proceed if escrow already passed its own checks.

Any distinct SD TEE is future/non-conforming for V2 S2-7 until S2-3 and S2-6 define the attested channel, DEK availability, quote binding, zeroization proof, and failure semantics. A future conforming design must satisfy all of these requirements:

- It receives plaintext only over an attested in-TEE channel from the ingestion TEE.
- It has its own binary measurement registered through S2-6 ceremony.
- Its quote binds `authorizationId`, `h_commit` once available, `pda_root`, `schema_digest`, SD plan digest, and SD binary measurement.
- It zeroizes plaintext, witnesses, and salts before returning.
- Its failure cannot block escrow commit finalization.

Until those requirements are normatively specified and tested, partner-ready implementations must not use a separate SD TEE.

### §2.3 Synchronous-with-escrow timing

SD outputs are delivered in the onboarding response. The partner must not be asked to poll later for proofs over the same plaintext. If proof generation exceeds the configured onboarding timeout, SD fails for that onboarding and returns an SD failure object while escrow continues. The partner may retry by initiating a fresh commit with fresh plaintext, fresh nonce, fresh DEK, and fresh SD salts. It may not ask Cealis to generate new proofs from the already-destroyed plaintext.

The recommended default timeout budget for Stage 3 is:

| Stage | Budget |
|---|---:|
| field canonicalization | 100 ms |
| salt derivation + commitments | 100 ms |
| Merkle tree build | 50 ms for <= 256 fields |
| witness generation | 500 ms per Claim |
| PLONK proof generation | 2 s per Claim initially; measured Stage 3 budget replaces this |
| response assembly | 100 ms |

Timeouts are operational budgets, not security limits. Exceeding a timeout fails SD, not escrow.

### §2.4 Salt derivation via HKDF from DEK

The SD pipeline derives a 32-byte `sd_master_salt` from the escrow DEK inside the TEE. The salt schedule is intentionally pre-root: it binds only fields available before `sdMerkleRoot` and `commit_AAD` finalization, and it never consumes final `h_commit`, `commit_context_digest`, `aad_digest`, or `sdMerkleRoot`.

```
sd_salt_context_digest = keccak256(
  TAG_SD_SALT_CONTEXT_V3
  || authorizationId
  || pda_root
  || schema_digest
  || partner_id
  || sd_plan_digest
)

sd_master_salt = HKDF-SHA256(
  salt = TAG_SD_SALT_V3 || sd_salt_context_digest,
  ikm  = DEK,
  info = "cealis-sd-master-salt-v3",
  L    = 32
)
```

`sd_salt_context_digest` is the unique salt context for a commit's SD sidecar. It is partner- and plan-bound, but acyclic with respect to `sdMerkleRoot`: SD uses it to create field commitments and the Merkle root, then S2-1 binds that root through `commit_AAD.sdMerkleRoot -> aad_digest -> final h_commit`. There is no final-commit or zero-placeholder production fallback. Any implementation that attempts to derive salts from final `h_commit`, `commit_context_digest`, `aad_digest`, `sdMerkleRoot`, or a zero placeholder is non-conforming.

Per-field salts derive as:

```
sd_field_salt_i = HKDF-SHA256(
  salt = TAG_SD_SALT_V3 || authorizationId || field_id || field_index_u32_be,
  ikm  = sd_master_salt,
  info = "cealis-sd-field-salt-v3",
  L    = 32
)
```

The output is converted to a BN254 scalar with rejection sampling: if `OS2IP(output) >= p`, expand with an appended counter byte in the HKDF info string (`...-v3/1`, `...-v3/2`, etc.) until the value is `< p`. Expected retries are negligible because `p` is close to 2^254. Modulo reduction is forbidden for salts because salt collisions would weaken binding.

### §2.5 Salt ephemerality

`sd_master_salt` and every `sd_field_salt_i` exist only inside the TEE process memory. They are never returned to partners, never stored in vault, never committed on-chain, never written to logs, and never included in crash dumps. They are zeroized after all field commitments and witnesses are generated.

The partner verifies commitments without salts by trusting the TEE attestation chain plus the binding of commitments/proofs to the same `authorizationId`, final `h_commit`, and `sd_salt_context_digest`. Cleartext fields are verified by a TEE-produced opening proof, not by disclosing the salt. The opening proof is either a PLONK equality proof for the cleartext value or a non-ZK `cleartext_attestation_digest` signed/attested by the SD TEE per §8.1. The default is to include an equality proof for every cleartext field when the partner needs cryptographic self-verification without trusting an additional TEE signature.

### §2.6 Plaintext destruction post-TEE

Plaintext, normalized field values, witness assignments, and SD salts must be destroyed after escrow encryption and SD output assembly. "Destroyed" at the software layer means overwritten/zeroized where the runtime permits, references dropped, buffers excluded from logs/crash dumps, and no persistence outside the TEE. "Destroyed" at the architecture layer means no API exists to ask Cealis for a later proof over the same plaintext. A later proof requires a fresh commit.

## §3 - TAG_SD_*_V3 family

### §3.1 Construction discipline

Every SD tag is a 32-byte keccak-256 digest:

```
TAG_SD_NAME_V3 = keccak256(bytes("CEALIS_SD_NAME_V3"))
```

The label string is ASCII, no NUL terminator, no trailing newline. Production code uses the precomputed `bytes32` value at construction sites. Raw label strings at construction sites are forbidden except in tag-table self-tests.

S2-7 uses `CEALIS_SD_` labels to stay disjoint from S2-1 `CEALIS_V3_` labels. A collision in label, digest, or construction purpose between SD and escrow namespaces is a specification defect.

### §3.2 Active tag table

| Symbol | Label string | Use |
|---|---|---|
| `TAG_SD_COMMIT_V3` | `CEALIS_SD_COMMIT_V3` | SD commitment bundle digest and top-level SD bundle identity |
| `TAG_SD_FIELD_ID_V3` | `CEALIS_SD_FIELD_ID_V3` | `field_id` derivation from schema path/type |
| `TAG_SD_FIELD_V3` | `CEALIS_SD_FIELD_V3` | per-field Poseidon commitment domain separator |
| `TAG_SD_PROOF_V3` | `CEALIS_SD_PROOF_V3` | PLONK proof context and public-input binding |
| `TAG_SD_MERKLE_V3` | `CEALIS_SD_MERKLE_V3` | Merkle node domain separator and tree root context |
| `TAG_SD_SALT_V3` | `CEALIS_SD_SALT_V3` | HKDF salt derivation context |
| `TAG_SD_NULLIFIER_V3` | `CEALIS_SD_NULLIFIER_V3` | nullifier/replay-protection id |
| `TAG_SD_CLAIM_V3` | `CEALIS_SD_CLAIM_V3` | partner Claim id and Claim digest |
| `TAG_SD_CLEARFIELD_V3` | `CEALIS_SD_CLEARFIELD_V3` | cleartext field opening context |
| `TAG_SD_VERIFIER_V3` | `CEALIS_SD_VERIFIER_V3` | verifier ref derivation for circuit/verifier version |
| `TAG_SD_PLAN_V3` | `CEALIS_SD_PLAN_V3` | PDA SD plan digest |
| `TAG_SD_SALT_CONTEXT_V3` | `CEALIS_SD_SALT_CONTEXT_V3` | acyclic pre-root salt context digest for SD salt derivation |

### §3.3 Required byte preimages

The following fixed-width preimages are normative:

```
sd_bundle_digest = keccak256(
  TAG_SD_COMMIT_V3
  || authorizationId
  || h_commit
  || pda_root
  || partner_id
  || sdMerkleRoot
  || sd_salt_context_digest
  || sd_plan_digest
)
```

```
claim_id = keccak256(
  TAG_SD_CLAIM_V3
  || partner_id
  || pda_id
  || pda_version_u64_be
  || claim_index_u32_be
  || claim_ast_digest
)
```

```
proof_context_digest = keccak256(
  TAG_SD_PROOF_V3
  || authorizationId
  || h_commit
  || partner_id
  || pda_id
  || claim_id
  || verifier_ref
  || expiry_timestamp_u64_be
)
```

```
nullifier = keccak256(
  TAG_SD_NULLIFIER_V3
  || authorizationId
  || partner_id
  || claim_id
  || field_id
)
```

`disclosure_id` is the unified Claim-proof policy handle (collapsed from prior `revocation_id`/`disclosure_id` split per Phase 2b H-1). It is computed at on-chain disclosure registration per §D.6 and serves as the single key for both registration events and revocation lookups. The on-chain `DisclosureRevocationRegistry` is keyed by `disclosure_id` only; there is no separate `revocation_id` digest. For off-chain-only Claim proofs (no on-chain registration), the SDK MAY compute a synthetic `disclosure_id` using the §D.6 preimage as a deterministic policy handle even when no chain registration occurs.

Every multi-byte integer in these keccak preimages is big-endian. Variable-length Claim ASTs are first canonicalized and hashed to fixed-width digests before entering these preimages.

### §3.4 SD tag authority and S2-1 META note

S2-7 is canonical for the active `TAG_SD_*_V3` family above: `TAG_SD_COMMIT_V3`, `TAG_SD_FIELD_ID_V3`, `TAG_SD_FIELD_V3`, `TAG_SD_PROOF_V3`, `TAG_SD_MERKLE_V3`, `TAG_SD_SALT_V3`, `TAG_SD_NULLIFIER_V3`, `TAG_SD_CLAIM_V3`, `TAG_SD_CLEARFIELD_V3`, `TAG_SD_VERIFIER_V3`, `TAG_SD_PLAN_V3`, and `TAG_SD_SALT_CONTEXT_V3`. `TAG_SD_REVOCATION_V3` is RETIRED in Phase 2b (H-1 collapse); `disclosure_id` per §D.6 is the unified Claim-proof policy handle keyed under `TAG_SD_COMMIT_V3`. S2-1 §2.7 may cross-reference this namespace, but S2-1 must not invent aliases or stale examples such as `TAG_SD_FIELD_COMMITMENT_V3`, `TAG_SD_MERKLE_LEAF_V3`, or `TAG_SD_BUNDLE_V3`. Patching stale S2-1 examples is deferred to the A4-style cross-stack backprop; S2-7's table remains the SD tag source of truth.

Because these are SD-namespace tags rather than `CEALIS_V3_` escrow tags, their presence alone does not define escrow-core tag preimages.

## §4 - Per-field Poseidon commitment

### §4.1 Poseidon over BN254

Per-field commitments use Poseidon over BN254 scalar inputs. The default arity for leaf commitments is 5 inputs:

```
field_commitment = Poseidon5(
  tag_field_scalar,
  authorization_scalar,
  field_id_scalar,
  salt_field_scalar,
  value_scalar
)
```

Where:

- `tag_field_scalar = OS2IP(TAG_SD_FIELD_V3) mod p`.
- `authorization_scalar = OS2IP(authorizationId) mod p`.
- `field_id_scalar = OS2IP(field_id) mod p`.
- `salt_field_scalar` is the rejection-sampled per-field salt scalar from §2.4.
- `value_scalar` is the canonical scalar encoding of the field value per §4.2.

The commitment output is a BN254 scalar. EVM-facing bundles encode it as `uint256` constrained to `< p`.

### §4.2 Field encoding

Each field type maps to exactly one scalar or a bounded vector of scalars. Predicate circuits state which form they accept.

| Type | Scalar encoding |
|---|---|
| string | UTF-8 NFC normalization, then `keccak256(bytes)` reduced through hash-to-field; max length configured per schema |
| uint | unsigned integer value directly, must be `< p` and within schema bit width |
| int | sign-magnitude mapping: non-negative `x -> 2x`, negative `-x -> 2x-1`; result `< p` |
| bool | `0` false, `1` true |
| bytes | `keccak256(bytes)` reduced through hash-to-field; raw bytes never enter circuit unless schema caps length and circuit supports chunking |
| date | Unix day number as unsigned integer; timestamp proofs use seconds if schema says timestamp |
| decimal_fixed | scaled integer using schema-declared decimal places; scale is part of schema digest |
| enum | schema-declared ordinal starting at 1; 0 reserved for absent/null where schema permits |
| country_code | ISO alpha-2 upper-case encoded as `(byte0 << 8) + byte1` |
| address | EVM address as 160-bit unsigned integer |
| object_hash | already-hashed bytes32 reduced through hash-to-field |

Null handling is schema-explicit. A nullable field encodes absence as a pair `(present = 0, value = 0)` in circuits that need absence semantics. A non-nullable absent field fails schema validation before SD.

### §4.3 Per-field salt derivation

Field salts are derived after schema validation and before commitment generation. The derivation binds `authorizationId`, `field_id`, and deterministic `field_index`. `field_index` is the leaf order index from §5.3, not the source JSON order. This prevents two schema-equivalent payloads with different JSON ordering from producing different salt contexts.

Salt reuse across fields is forbidden. Salt reuse across commits is prevented by fresh DEK and `authorizationId`. If a Stage 3 implementation detects duplicate `(authorizationId, field_id, field_index)` during SD plan execution, it must abort SD with `ERR_SD_FIELD_POLICY_UNKNOWN` or a more specific implementation error and continue escrow per §15.

### §4.4 Cleartext-field opening discipline

A partner receiving a cleartext field needs to verify that the cleartext belongs to the same committed SD tree. Because salts are not disclosed, the default verification path is an equality proof:

```
Prove:
  field_commitment = Poseidon5(tag, authorization_scalar, field_id, salt, value)
  value = public_cleartext_encoded
  leaf(field_id, field_commitment, policy) is in sdMerkleRoot
```

The partner verifies the proof and then accepts the cleartext. If a partner chooses a TEE-attestation-only opening mode for performance, the onboarding response must mark that field as `cleartext_attested` rather than `cleartext_zk_opened`, and the partner must understand that verification rests on the SD TEE attestation chain rather than a circuit proof. The default for regulated partner integrations is `cleartext_zk_opened`.

### §4.5 Field commitment storage discipline

Per-field commitments are included in the partner onboarding response and may be stored by the partner. Cealis may store commitments as non-secret audit metadata, but must treat them as pseudonymous partner onboarding records because field ids and Claim context can leak subject facts. Salts and witnesses are never stored. The vault does not need SD commitments to perform escrow reveal. Deleting SD commitment metadata must not affect escrow ciphertext storage or reveal correctness.

## §5 - sdMerkleRoot construction

### §5.1 Binary Poseidon Merkle tree

`sdMerkleRoot` is the root of a binary Poseidon Merkle tree over deterministic SD leaves. Leaves are Poseidon hashes:

```
leaf_i = Poseidon5(
  tag_merkle_scalar,
  field_index_scalar,
  field_id_scalar,
  field_commitment_i,
  policy_code_scalar
)
```

`tag_merkle_scalar = OS2IP(TAG_SD_MERKLE_V3) mod p`. `policy_code` is `1 cleartext`, `2 zkp`, `3 escrow_only`. Including `escrow_only` leaves is mandatory for fields in the SD plan's schema subset so the partner can verify that omitted fields were intentionally omitted, not dropped after TEE processing. The configurator may define the SD plan subset as the full schema or a named sub-schema; that choice is part of `sd_plan_digest`.

Internal nodes are:

```
node = Poseidon3(tag_merkle_scalar, left_child, right_child)
```

### §5.2 Tree shape

The tree is a complete binary tree with depth `d = max(1, ceil_log2(leaf_count))` where `2^d >= leaf_count`. `d` must be between 1 and 16 for V2 launch, supporting 1 to 65,536 SD leaves. Stage 3 may lower default operational caps per PDA archetype, but the circuit family must support the full depth range through versioned circuits or a max-depth circuit with zero padding.

Padding leaves use:

```
padding_leaf_j = Poseidon5(tag_merkle_scalar, j, 0, 0, 0)
```

where `j` is the padded leaf index. Padding leaves are never valid field openings because `field_id = 0` is reserved.

A one-leaf SD plan is represented as a depth-1 tree with `target = 2`: the real leaf is index 0 and one padding leaf at index 1 is included. This avoids a depth-0 special case and gives every disclosed field a non-empty Merkle path shape.

### §5.3 Leaf canonical ordering

Leaves are ordered by:

1. ascending `field_path_hash`,
2. then ascending `field_type_code`,
3. then ascending `field_id`,
4. then stable schema declaration order as a final tie-breaker.

The tie-breaker should never be needed if schema paths are unique, but it makes the algorithm total. JSON input order is ignored. Partner SDKs must recompute ordering from schema metadata, not from response ordering alone.

### §5.4 Binding into escrow context

The binding for `commit_version = 0x0302` is:

```
commit_AAD.sdMerkleRoot = sdMerkleRoot
```

Current S2-1 `CommitAAD` includes `sdMerkleRoot`; S2-7 defines the SD-side root and bundle digest that populate that field. The SD bundle digest remains the partner-facing artifact identity:

```
sd_bundle_digest = keccak256(
  TAG_SD_COMMIT_V3
  || authorizationId
  || h_commit
  || pda_root
  || partner_id
  || sdMerkleRoot
  || sd_salt_context_digest
  || sd_plan_digest
)
```

The partner verifies that the SD bundle references the same `authorizationId`, `h_commit`, `pda_root`, and `partner_id` as the escrow commit; that `sd_salt_context_digest` recomputes from §2.4 fields; and that `commit_AAD.sdMerkleRoot == sdMerkleRoot`. Public or audit copy may claim AEAD-bound SD root only for `commit_version = 0x0302` or later.

### §5.5 Partner root verification

For `commit_version = 0x0302`, the partner verifies:

1. `sdMerkleRoot` is present in the onboarding response.
2. Every disclosed field/proof includes a Merkle path to `sdMerkleRoot`.
3. `sd_salt_context_digest` recomputes from `authorizationId`, `pda_root`, `schema_digest`, `partner_id`, and `sd_plan_digest`.
4. `sd_bundle_digest` recomputes from the received root, salt context, and commit identifiers.
5. `commit_AAD.sdMerkleRoot` exists, is non-zero for SD-enabled commits, and equals `sdMerkleRoot`.

Failing step 3 is `ERR_SD_SALT_DERIVATION_FAIL` or an SDK-specific `ERR_SD_SALT_CONTEXT_MISMATCH`. Failing step 5 is `ERR_SD_ROOT_BINDING_MISSING` or `ERR_SD_MERKLE_PATH_INVALID` depending on whether the field is absent or mismatched. Historical/pre-`0x0301` compatibility is confined to App. J.

## §6 - Predicate types

### §6.1 Claim structure

An SD Claim is a bounded predicate expression over one or more fields. Canonical Claim form:

```scale
struct SdClaim {
  claim_id: [u8; 32],
  partner_id: [u8; 32],
  pda_id: [u8; 32],
  pda_version: u64,
  authorizationId: [u8; 32],
  h_commit: [u8; 32],
  sdMerkleRoot: uint256,
  expiry_timestamp: u64,
  disclosure_id: [u8; 32],
  expression_digest: [u8; 32],
  verifier_ref: [u8; 32],
}
```

The Claim body is canonicalized to `expression_digest` before entering EVM-facing hashes. Circuit-specific public inputs include the semantic components in fixed order per §7.6; they do not parse SCALE inside the verifier.

### §6.2 Range predicate

Range proves:

```
min <= value <= max
```

for integer-like encodings: `uint`, non-negative `int`, date, timestamp, decimal_fixed, enum ordinal when semantically meaningful, and age-derived values computed from date-of-birth. Range bounds are public inputs. The circuit must constrain:

- committed value opens to the leaf commitment,
- value bit decomposition is within the configured bit width,
- lower-bound comparison passes,
- upper-bound comparison passes,
- field leaf is in `sdMerkleRoot`,
- Claim binding public inputs match.

For date-of-birth to age proofs, the circuit should not expose birth date. It uses public `as_of_day` and proves `birth_day <= as_of_day - min_age_days` and any upper bound if configured.

### §6.3 Equality predicate

Equality proves:

```
value == expected_value
```

without disclosing the witness unless the expected value itself is the disclosed value. Equality is used for cleartext openings, country-code checks, issuer-mode flags, enum equality, and exact partner-required attributes. The expected value scalar is a public input. The circuit constrains committed witness value equals expected scalar and verifies Merkle membership.

If equality over a high-entropy bytes/string field would leak the value by making `expected_value` public, the PDA must classify that field as `cleartext` or use set membership over a committed set root instead.

### §6.4 Set membership predicate

Set membership proves:

```
value ∈ set
```

Two set forms are supported:

1. Inline bounded set, for sets up to 32 scalar values.
2. Merkle set root, for larger sets.

Inline sets are public inputs sorted ascending, padded with zeros, with a public `set_length`. The circuit checks equality against at least one member and enforces padding zeros beyond `set_length`.

Merkle sets use a second Poseidon Merkle path inside the circuit:

```
set_leaf = Poseidon3(tag_claim_scalar, set_member_index, value)
set_root = configured public input
```

The set root must be part of the PDA SD Claim configuration and included in `expression_digest`. This prevents a partner from verifying the proof against a different set after onboarding.

### §6.5 Non-equality predicate

Non-equality proves:

```
value != forbidden_value
```

For scalar fields, the circuit uses a standard inverse witness:

```
diff = value - forbidden_value
diff * inv = 1
```

Existence of `inv` proves `diff != 0`. The forbidden value is public. Non-equality over string/bytes fields uses their canonical scalar encodings and inherits collision resistance from the hash-to-field mapping; for high-value legal predicates, prefer enum or bounded-string normalization before non-equality.

### §6.6 Composition

S2-7 has four primitive predicate families: range, equality, set membership, and non-equality. `composed` is a Claim wrapper over those leaf families, not a fifth leaf predicate. A composed Claim may use bounded `AND`, `OR`, and `NOT` only when every leaf predicate is one of the four families and the expression tree stays within the caps below.

Composition is not an arbitrary programming language. The canonical expression tree has:

- max depth 8,
- max leaf predicates 32,
- max fields per Claim 16,
- no unbounded loops,
- no floating point,
- no locale-sensitive string comparison,
- no external calls,
- no current time reads except public `as_of_timestamp` supplied to the proof.

`AND` requires all child predicates true. `OR` requires at least one child true and must hide which branch only if the circuit is specifically built as branch-private; the default OR circuit exposes branch selector as a public input to keep constraints smaller. `NOT` may wrap only equality, set membership, or bounded boolean subclaims where the resulting semantics are unambiguous. `NOT(range)` is represented as a configured OR of two ranges.

### §6.7 Claim replay protection

Every proof binds:

- `authorizationId`,
- `h_commit`,
- `partner_id`,
- `pda_id`,
- `pda_version`,
- `claim_id`,
- `field_id` or ordered field id list,
- `sdMerkleRoot`,
- `expiry_timestamp`,
- `disclosure_id`,
- `verifier_ref`.

A proof from one partner, PDA, commitment, Claim, verifier version, or expiry context must not verify under another. Replays fail through public-input mismatch or revocation/expiry checks.

## §7 - PLONK circuits on BN254

### §7.1 Universal setup

S2-7 uses PLONK over BN254 with a universal trusted setup. Stage 3 must pin the specific Powers-of-Tau transcript, contribution hash chain, proving library, verifier generator, and ceremony verification command in S2-3/S2-6. S2-7 requires that every deployed verifier ref include:

- circuit family,
- circuit version,
- max tree depth,
- max field bit width,
- public-input schema version,
- proving-key digest,
- verification-key digest,
- setup transcript digest,
- effective block,
- tombstone block,
- deprecation flag.

The verifier ref derivation is:

```
verifier_ref = keccak256(
  TAG_SD_VERIFIER_V3
  || circuit_family_id
  || circuit_version_u32_be
  || verification_key_digest
  || public_input_schema_digest
)
```

### §7.2 Circuit topology

Each predicate circuit has four layers:

1. **Commitment layer:** recompute per-field Poseidon commitment from private salt and private value.
2. **Merkle layer:** verify the leaf path from commitment to `sdMerkleRoot`.
3. **Predicate layer:** enforce range/equality/set/non-equality semantics.
4. **Binding layer:** constrain public inputs to Claim context and compute the proof context digest where applicable.

Multi-field Claims can either use one aggregate circuit or multiple per-field proofs with an outer Claim aggregation proof. The Stage 3 default should be aggregate circuits for small Claims and multiple proofs for large Claims. The partner SDK must abstract both forms into one `verifyClaim()` API.

### §7.3 Custom gates vs vanilla PLONK

The default is vanilla PLONK plus Poseidon custom gates if the proving stack supports them without verifier fragmentation. Poseidon custom gates are allowed because they materially reduce constraint count and are standard in BN254 ecosystems. Range-check custom gates are allowed if the verification-key metadata names them explicitly.

No custom gate may be introduced without:

- verifier ref version bump,
- circuit metadata update,
- Stage 3 fixed vectors,
- S2-6 verifier deployment ceremony,
- backward-compatible partner SDK support for older verifier refs.

### §7.4 Witness generation pipeline

Witness generation runs inside the SD TEE boundary. Inputs:

- plaintext field values,
- schema metadata,
- PDA SD field mapping,
- partner Claim configuration,
- per-field salts,
- `authorizationId`,
- `h_commit`,
- `pda_root`,
- `partner_id`,
- `sdMerkleRoot`,
- expiry timestamp.

Witness generation must fail before proof generation if any field is missing, malformed, nullable without configured absence semantics, out of range for its declared type, or mapped `escrow_only` while referenced by a Claim. Witness files must never be persisted outside the TEE. If the proving library writes temporary files, the implementation must mount a TEE-local encrypted tmpfs and wipe it before returning.

### §7.5 Proof generation pipeline

Proof generation runs synchronously during onboarding. A proof is generated only after all field commitments and `sdMerkleRoot` are fixed. If proof generation fails for one Claim, the SD response marks that Claim failed and omits any proof for it; it must not include partial witnesses or internal errors. Other Claims may succeed. The top-level SD status can be:

| Status | Meaning |
|---|---|
| `complete` | every configured cleartext/proof output succeeded |
| `partial` | at least one output succeeded and at least one failed |
| `failed` | no configured SD output succeeded |
| `not_configured` | PDA has SD disabled |

Escrow commit success is independent of this SD status.

### §7.6 Public input ordering

All SD PLONK verifier contracts use fixed public input order:

| Index | Input |
|---:|---|
| 0 | `authorization_scalar` |
| 1 | `h_commit_scalar` |
| 2 | `partner_scalar` |
| 3 | `pda_scalar` |
| 4 | `claim_scalar` |
| 5 | `field_set_digest_scalar` |
| 6 | `sdMerkleRoot` |
| 7 | `predicate_param_0` |
| 8 | `predicate_param_1` |
| 9 | `predicate_param_2` |
| 10 | `expiry_timestamp` |
| 11 | `revocation_scalar` |
| 12 | `verifier_ref_scalar` |
| 13 | `proof_context_scalar` |

Unused predicate params are zero. Aggregate circuits that need more public inputs must define a new `public_input_schema_digest` and verifier ref. They may not overload these positions.

### §7.7 Off-chain and on-chain verification

Partner-side verification is mandatory and off-chain by default. On-chain verification is optional and used only when a partner or downstream protocol needs a proof result visible to Base. The same proof must verify under both paths if the verifier ref points to an on-chain verifier. Off-chain SDKs must not accept a proof that the on-chain verifier would reject under the same public inputs.

### §7.8 Circuit version pinning and upgrades

Circuit versions are append-only. A new circuit version creates a new `verifier_ref`. Existing Claim proofs remain verifiable under the old verifier until expiry or Claim-proof revocation. Tombstoning a verifier blocks new proofs from being generated under that verifier but does not retroactively invalidate proofs generated before tombstone unless the revocation registry marks affected disclosures revoked.

### §7.9 Constraint-count budget

Initial Stage 3 budgets:

| Circuit | Target constraints | Max constraints before redesign |
|---|---:|---:|
| equality + Merkle depth 16 | <= 35k | 60k |
| non-equality + Merkle depth 16 | <= 40k | 70k |
| range 64-bit + Merkle depth 16 | <= 55k | 90k |
| inline set membership 32 + Merkle depth 16 | <= 80k | 130k |
| Merkle-set membership depth 16 + field Merkle depth 16 | <= 100k | 160k |
| aggregate Claim, 8 leaves | <= 250k | 400k |

Exceeding target is not automatically invalid, but exceeding max requires a spec erratum or circuit redesign before partner deployment.

## §8 - Synchronous delivery in onboarding response

### §8.1 Payload shape

S2-5 owns HTTP wire format. S2-7 owns the semantic payload:

```json
{
  "sd_version": "s2-7-1.0",
  "status": "complete",
  "authorizationId": "0x...",
  "h_commit": "0x...",
  "pda_root": "0x...",
  "partner_id": "0x...",
  "schema_digest": "0x...",
  "sdMerkleRoot": "0x...",
  "sd_salt_context_digest": "0x...",
  "sd_plan_digest": "0x...",
  "sd_bundle_digest": "0x...",
  "rootBindingLevel": "commit_AAD",
  "cleartext": [],
  "claims": [],
  "revocationRegistry": "0x...",
  "generated_at": "2026-05-04T00:00:00Z"
}
```

For `commit_version = 0x0302`, `rootBindingLevel` is always `commit_AAD`. Historical/pre-`0x0301` compatibility handling lives only in App. J.

A cleartext item contains:

```json
{
  "field_id": "0x...",
  "field_path": "kyc.country",
  "encoding": "country_code",
  "value": "DE",
  "field_commitment": "0x...",
  "merkle_path": ["0x..."],
  "opening_mode": "cleartext_zk_opened",
  "opening_proof": { "verifier_ref": "0x...", "proof": "0x...", "public_inputs": [] }
}
```

A Claim item contains:

```json
{
  "claim_id": "0x...",
  "claim_type": "range",
  "field_ids": ["0x..."],
  "verifier_ref": "0x...",
  "proof": "0x...",
  "public_inputs": [],
  "expiry_timestamp": 1798761600,
  "disclosure_id": "0x..."
}
```

### §8.2 Partner-side reception protocol

The partner must:

1. Validate JSON/schema shape.
2. Verify `authorizationId`, `h_commit`, `pda_root`, `partner_id`, and `schema_digest` match the escrow onboarding object.
3. Recompute `sd_plan_digest` from PDA SD config.
4. Recompute every cleartext field encoding.
5. Verify every Merkle path to `sdMerkleRoot`.
6. Verify every cleartext opening proof where `opening_mode = cleartext_zk_opened`.
7. Verify every Claim proof.
8. Check proof expiry.
9. Check revocation registry state unless policy allows offline grace.
10. Store only the minimum SD artifacts required for partner business purpose.

### §8.3 Day-one verification at partner

Partner systems must not treat SD payload receipt as verified. They accept a field/Claim only after SDK verification returns `valid`. The partner application can choose to block user onboarding if configured SD outputs fail, but that is outside escrow cryptography. The partner must not ask Cealis to "repair" proofs post-commit; repair requires fresh commit.

### §8.4 Forward reference to S2-5

S2-5 defines endpoint routes, idempotency, retries, payload compression, authentication, API error transport, webhook shape, and partner callback behavior. S2-7 requires S2-5 to preserve semantic field names and not strip proofs, public inputs, Merkle paths, binding level, expiry, or revocation ids.

## §9 - Partner verification SDK

### §9.1 SDK shape

The default SDK package is TypeScript/Node, with browser and Rust bindings as later implementation surfaces. The normative API shape:

```ts
type VerifySdBundleResult = {
  status: "valid" | "partial" | "invalid";
  rootBindingLevel: "commit_AAD";
  acceptedClaims: string[];
  rejectedClaims: { claimId: string; error: string }[];
  acceptedCleartextFields: string[];
  rejectedCleartextFields: { fieldId: string; error: string }[];
};

async function verifySdBundle(input: {
  escrowCommit: EscrowCommitReference;
  sdBundle: SdBundle;
  pdaSdConfig: PdaSdConfig;
  verifierRegistry: VerifierRegistryClient;
  revocationRegistry: RevocationRegistryClient;
  now: Date;
}): Promise<VerifySdBundleResult>;
```

### §9.2 ZKP verification

The SDK loads `verifier_ref`, resolves the verification key or verifier contract, checks public input schema, checks proof length/format, and verifies the proof. It must reject unknown verifier refs, tombstoned-before-generation verifiers, public input length mismatch, and non-canonical scalar encodings.

### §9.3 Root verification against escrow context

The SDK verifies root binding against `commit_AAD.sdMerkleRoot`. Absence, zero root for a completed SD-enabled commit, mismatch with the bundle root, or any non-`commit_AAD` active result for `commit_version = 0x0302` is invalid. The only zero-root SD-enabled case is `sd_failed_before_root` per App. J, where the SDK rejects SD outputs but does not mark escrow invalid.

### §9.4 Cleartext-field verification

For every cleartext field, the SDK canonicalizes the received value, verifies its Merkle path, and verifies the opening proof or TEE attestation. It must display `cleartext_attested` and `cleartext_zk_opened` as distinct verification modes in machine-readable output.

`rejectedClaims` may include expiry and revocation failures. `rejectedCleartextFields` may include malformed value, Merkle mismatch, failed opening proof, or failed TEE attestation, but not revocation; cleartext delivery is not a revocable SD protocol object.

### §9.5 Trust assumptions

A partner accepting SD trusts:

- the G4/SD TEE attestation chain for correct execution and salt secrecy,
- the circuit/verifier registry for correct verification keys,
- the partner SDK implementation,
- the binding between SD artifacts and escrow commit,
- expiry/revocation checks being performed at decision time.

The partner does not need to trust Cealis to store plaintext after commit, because no post-commit SD generation exists. The partner does need to trust that the TEE did not exfiltrate plaintext during Mode A processing; this is the same Mode A trust structure named in the WP.

### §9.6 Failure modes and caller recovery

SDK failures are caller-visible but do not alter escrow state. Recovery options:

| Failure | Recovery |
|---|---|
| malformed bundle | partner rejects onboarding response; fresh commit required |
| proof invalid | reject Claim; fresh commit required |
| Merkle mismatch | reject bundle; investigate implementation or tampering |
| expired Claim proof | request fresh commit if partner needs current proof |
| revoked Claim proof | reject proof; follow partner compliance flow |
| registry unavailable | retry within partner-defined offline grace if allowed |
| missing or mismatched `commit_AAD.sdMerkleRoot` | reject active `0x0302` bundle, except `sd_failed_before_root` which has no usable SD output |

## §10 - On-chain PLONK verifier contract

### §10.1 Verifier shape

S2-7 extends S2-2's minimal `IDisclosureRegistry` with verifier registry and revocation checks. On-chain verification is optional per Claim, but when deployed it must use standard Solidity custom errors, UUPS upgrade discipline, and Timelock-controlled verifier registration.

```solidity
interface ISdPlonkVerifier {
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool);
}
```

Verifier contracts must not store plaintext, salts, witnesses, or proof-generation state. They verify only proof bytes and public inputs.

### §10.2 Per-circuit verifier vs generic verifier

The default is per-circuit verifier contracts generated by the proving stack. A generic verifier adapter is allowed only if it dispatches by `verifier_ref` to immutable verification keys registered on-chain and has gas bounded by the same limits. Per-circuit verifiers are easier to audit and should be preferred for first implementation.

### §10.3 Gas budget bounds

Initial gas budgets:

| Operation | Target | Max before redesign |
|---|---:|---:|
| equality proof verify | <= 350k | 550k |
| range proof verify | <= 450k | 700k |
| set membership verify | <= 600k | 900k |
| aggregate Claim verify | <= 900k | 1.5M |
| revocation check | <= 60k | 120k |
| disclosure commit | <= 120k | 220k |

On-chain verification must never be required for escrow commit or reveal. It is a partner/composability surface only.

### §10.4 Upgrade discipline

Verifier registries are append-only. Existing verifier contracts are not upgraded in place unless a critical bug requires deprecation. New verifier versions receive new `verifier_ref` values. TimelockController owns `UPGRADER_ROLE` for registry contracts. Generated verifier contracts should be immutable where possible; if proxied, storage layout must be append-only and no verification-key field may be overwritten.

## §11 - Claim-proof expiry and revocation

S2-7 revocation is scoped to Claim-proof reliance. `expiry_timestamp`, `disclosure_id`, and `SdRevocationRecord` apply to `SdClaimItem` proofs and their policy validity. They do not revoke cleartext values, field commitments, Merkle roots, or already-delivered commitment/opening artifacts. Cleartext delivery is never revocable through the SD protocol; only future reliance or downstream use is contractual and partner-governed.

### §11.1 Layer 1: Claim-proof expiry

Every SD Claim has an `expiry_timestamp` public input. The partner SDK rejects Claim proofs after expiry. On-chain verifier adapters that expose `verifyAndCommitDisclosure` must also check expiry against `block.timestamp` unless the caller explicitly uses a pure `verifyProof` view that performs no policy checks.

Expiry is per Claim, not per bundle. A country-residence proof may expire after 30 days; an over-18 proof may be valid for years depending on partner policy; a sanctions-screening proof may expire after hours. Expiry defaults live in PDA templates and are finalized in S2-4.

### §11.2 Layer 2: on-chain Claim-proof revocation registry

The SD revocation registry is isolated from escrow contracts:

```solidity
interface IDisclosureRevocationRegistry {
    error DisclosureUnknown(bytes32 disclosureId);
    error DisclosureAlreadyRevoked(bytes32 disclosureId);
    error DisclosureRevocationUnauthorized(bytes32 disclosureId);
    event DisclosureRegistered(
        bytes32 indexed disclosureId,
        bytes32 indexed authorizationId,
        bytes32 indexed claimId,
        bytes32 verifierRef,
        uint64 expiryTimestamp,
        address authorizedRevoker
    );
    event DisclosureRevoked(
        bytes32 indexed disclosureId,
        bytes32 indexed authorizationId,
        uint8 reasonCode,
        bytes32 evidenceRef
    );

    function registerDisclosure(
        bytes32 disclosureId,
        bytes32 authorizationId,
        bytes32 claimId,
        bytes32 verifierRef,
        uint64 expiryTimestamp,
        address authorizedRevoker
    ) external;

    function revokeDisclosure(bytes32 disclosureId, uint8 reasonCode, bytes32 evidenceRef) external;
    function isRevoked(bytes32 disclosureId) external view returns (bool);
    function authorizedRevoker(bytes32 disclosureId) external view returns (address);
    function expiryTimestamp(bytes32 disclosureId) external view returns (uint64);
}
```

Roles follow S2-2 naming + §16.1. `ORCHESTRATOR_ROLE` registers disclosures. Two-tier revocation authority:

1. **`REVOCATION_ADMIN_ROLE`** — global Cealis-controlled. Always-can-revoke for Art. 17 subject erasure, legal compel, TEE integrity incidents (reason codes `0x01`, `0x05`).
2. **Per-disclosure `authorizedRevoker`** — partner-delegable. Address declared at `registerDisclosure` time, immutable per-disclosure. Partner-policy revocation (reason codes `0x03`, `0x06`) routes through this address. `0x0` means no partner delegation; only `REVOCATION_ADMIN_ROLE` can revoke.

The contract `canRevoke(disclosureId)` modifier passes if `hasRole(REVOCATION_ADMIN_ROLE, msg.sender)` OR `msg.sender == authorizedRevoker[disclosureId]`. Reverts with `DisclosureRevocationUnauthorized(disclosureId)` otherwise.

Timelock governs `REVOCATION_ADMIN_ROLE` grants and `UPGRADER_ROLE`. UPGRADER_ROLE is independent from `DisclosureRegistry`'s upgrader so revocation lifecycle can iterate without verifier ABI churn. Events contain no plaintext. Storage layout MUST reserve `uint256[50] private __gap;` per S2-2 §General UUPS discipline.

`isRevoked` and `revokeDisclosure` MUST revert with `DisclosureUnknown(disclosureId)` if the disclosure has not been registered (no default-allow on empty registry).

### §11.3 Revocation triggers

Claim-proof revocation triggers:

- PDA shred finalized: revoke all active unexpired SD Claim proofs for that `authorizationId`.
- Partner-initiated revocation: partner determines onboarding Claim proof should no longer be accepted.
- Subject-initiated revocation: subject exercises configured restriction/erasure path.
- Verifier deprecation: security governance revokes affected proof class.
- TEE integrity incident: Cealis revokes Claims generated by affected SD binary/verifier window.

Revocation does not delete partner-held proof bytes. It changes validity state for Claim proofs. Partner SDKs must check state before relying on a Claim proof.

### §11.4 Verifier integration

Off-chain SDK verification checks the Claim-proof revocation registry unless the PDA allows offline grace. On-chain `verifyAndCommitDisclosure` checks revocation in the same transaction via cross-contract `view`-call to `DisclosureRevocationRegistry.isRevoked(disclosureId)`. A Claim proof that is cryptographically valid but revoked returns invalid at policy layer. A cleartext item that passes Merkle/opening verification remains provenance-valid even if related Claim proofs are later revoked; partner contracts decide whether continued reliance is permitted.

**Pause fail-closed (mirrors S2-2 §9.15.1):** If `DisclosureRevocationRegistry` is paused, has zero address, or its `isRevoked` view reverts, then `verifyAndCommitDisclosure` MUST revert with `RevocationRegistryUnavailable`. SD verification cannot proceed when revocation state is unverifiable. This preserves the dual-layer revocation guarantee under operational pause.

### §11.5 Revocation reason codes

| Code | Meaning |
|---|---|
| `0x01` | subject erasure/restriction |
| `0x02` | PDA shred finalized |
| `0x03` | partner policy withdrawal |
| `0x04` | verifier/circuit deprecation |
| `0x05` | TEE integrity incident |
| `0x06` | claim generated under wrong PDA/config |

Reasons may be public because they are generic. Evidence refs may be encrypted CIDs where they would reveal PII.

## §12 - PDA field-mapping interaction

### §12.1 Per-field policy

The PDA SD plan contains:

```scale
struct SdFieldPolicy {
  field_id: [u8; 32],
  field_path_hash: [u8; 32],
  field_type_code: u8,
  policy: u8, // 1 cleartext, 2 zkp, 3 escrow_only
  allowed_claim_ids_root: [u8; 32],
  cleartext_opening_mode: u8, // 0 none, 1 zk_opened, 2 tee_attested
}
```

`allowed_claim_ids_root` prevents a partner from requesting a proof over a field that was not configured for that Claim. `cleartext_opening_mode` is zero unless policy is `cleartext`.

### §12.2 Schema-level SD availability

PDA+ governs whether a schema family permits SD. Some schemas may be escrow-only by platform policy because field normalization is too ambiguous, legal sensitivity is too high, or circuits are not registered. S2-4 must reject SD mappings for schemas without SD availability.

### §12.3 Configurator surface forward reference

S2-4 must implement:

- schema field browser,
- per-field `cleartext/zkp/escrow_only` selector,
- Claim builder for four predicate types,
- expiry defaults,
- revocation policy,
- Mode B rejection,
- proof-cost estimate,
- partner preview of onboarding payload,
- audit diff showing all non-`escrow_only` fields.

### §12.4 Default policy and opt-out

Default is `escrow_only`. SD is opt-in per PDA and per field. A partner cannot accidentally receive a field because the schema added a new property; new fields default to `escrow_only` until explicitly mapped. Removing SD from a field in a future PDA version affects future commits only; existing partner-held Claim proofs remain valid until expiry or Claim-proof revocation.

## §13 - Crypto-shredding interaction

### §13.1 DEK destruction makes salts unrecoverable

SD salts derive from the DEK through HKDF. Once the DEK is destroyed or unrecoverable because escrow gate material is unavailable and plaintext has been destroyed, SD salts cannot be regenerated. Vault deletion and shred state therefore make retroactive SD proof generation impossible.

### §13.2 Retroactive proof generation impossible

No Cealis API may accept "generate proof for existing commit" unless it is backed by a fresh recommit containing plaintext. A proof not emitted during onboarding cannot be added later. This is a structural property, not a missing feature.

### §13.3 Pre-shred outputs

Claim proofs already delivered to the partner remain cryptographically verifiable after shred because the partner holds proof bytes and public inputs. Whether they remain acceptable is policy-layer: expiry and Claim-proof revocation registry checks may reject them. For privacy-sensitive PDAs, shred finalization should automatically revoke all unexpired SD Claim proofs tied to the authorization.

Cleartext fields and field commitments already delivered at onboarding are not revoked by S2-7. They remain partner-held records with provenance. Shred blocks future escrow reveals and future proof generation, but it does not erase or protocol-revoke cleartext already delivered to a partner.

### §13.4 Revocation at shred time

When `ShredFinalized` is observed, the SD revocation worker enumerates active Claim-proof `disclosure_id`s for `authorizationId` and calls `revokeDisclosure(disclosure_id, 0x02, evidenceRef)`. This worker failure does not undo shred and does not affect escrow reveal/shred state. If revocation transaction fails, S2-6 operational alerting escalates until registry state matches shred state.

## §14 - Mode B incompatibility

### §14.1 Why Mode B and SD do not compose

Mode B means the subject's device performs encryption and Cealis never sees plaintext. This S2-7 pipeline requires plaintext inside an attested TEE to canonicalize fields, derive commitments, generate witnesses, and produce proofs. Without plaintext, Cealis cannot generate SD outputs. Having the device send only selected fields to Cealis would be a separate disclosure path and would violate the Mode B trust claim. Having the device generate proofs locally is a future client-side SD architecture, not this spec.

### §14.2 Configurator-level rejection

S2-4 must reject:

```
ingestion_mode = MODE_B && sd_enabled = true
```

with `ERR_SD_CONFIG_MODE_B_INCOMPATIBLE`. S2-5 must also reject any direct API request that attempts Mode B ingestion with SD options, even if configurator validation was bypassed. The rejection is defense-in-depth, not a negotiable partner setting.

Mode B with `sd_enabled = false` is valid and returns a disabled SD plan. The incompatibility is Mode B plus this TEE-side SD pipeline, not Mode B as an escrow mode.

### §14.3 Future direction

Client-side SD for Mode B would require subject-device witness generation, local proving keys, partner-verifiable client attestation or reproducible SDK verification, and a different salt story that does not depend on a TEE-held DEK. That is outside V2 S2-7. It must not be smuggled into this pipeline through a "hybrid" mode.

## §15 - Asymmetric pipeline isolation

### §15.1 SD failure does not block escrow

If SD fails, escrow commit continues if escrow checks pass. This is normative. SD is onboarding utility, not custody precondition. The only exception is application-level partner policy after commit: a partner may reject the user because it did not receive required onboarding proofs, but the escrow commitment remains valid unless explicitly shredded through normal mechanisms.

### §15.2 Failure modes by stage

| Stage | Failure | Escrow effect | SD effect |
|---|---|---|---|
| schema validation | field invalid for SD but valid for escrow | none | affected SD fields fail |
| salt derivation | HKDF failure | none | SD fails |
| commitment build | Poseidon library failure | none | SD fails |
| proving | witness/proof failure | none | Claim fails |
| response assembly | payload too large | none | SD partial/failed |
| partner verify | SDK rejects proof | none | partner rejects Claim |
| revocation check | registry unavailable | none | partner policy retry/offline grace |

### §15.3 Caller recovery boundary

Caller recovery is outside escrow crypto. The caller may retry partner onboarding with a fresh commit, accept partial SD, switch non-required fields to `escrow_only` in a future PDA version, or disable SD for future commits. The caller may not force post-commit proof generation and may not mark escrow commit invalid merely because SD failed.

## §16 - Test obligations

### §16.1 Unit tests

Stage 3 must test:

- tag digest computation for every `TAG_SD_*_V3`,
- field id derivation,
- every field type encoding,
- HKDF salt derivation and rejection sampling,
- Poseidon field commitments,
- Merkle tree padding/order/path verification,
- Claim id and proof context digest derivation,
- nullifier and revocation id derivation,
- public input order,
- every `ERR_SD_*` fail-closed path.

### §16.2 Circuit tests

For each Claim predicate type:

- valid witness passes,
- wrong salt fails,
- wrong value fails,
- wrong Merkle path fails,
- wrong root fails,
- wrong partner/PDA/authorization public input fails,
- expired Claim proof fails at policy layer,
- revoked Claim proof fails at policy layer,
- non-canonical scalar fails,
- max-depth tree passes.

### §16.3 Integration tests

End-to-end Mode A onboarding tests:

1. commit plaintext through Phase 2 TEE fixture,
2. encrypt escrow envelope,
3. generate SD commitments/proofs,
4. zeroize plaintext/salts,
5. return onboarding response,
6. partner SDK verifies,
7. escrow reveal path remains independent,
8. SD failure fixture still leaves escrow commit valid.

### §16.4 Partner SDK vectors

Stage 3 must publish JSON fixtures for:

- complete bundle,
- partial bundle,
- failed SD bundle,
- `commit_AAD.sdMerkleRoot` mismatch,
- cleartext equality opening,
- range proof,
- equality proof,
- set membership proof,
- non-equality proof,
- revoked Claim proof,
- expired Claim proof,
- Mode B rejection.

### §16.5 Crypto-shredding interaction tests

Tests must prove:

- post-shred proof generation API does not exist,
- shred finalization enqueues revocation of active SD Claim proofs, not cleartext fields or field commitments,
- partner-held Claim proof verifies cryptographically after shred but fails policy after revocation,
- partner-held cleartext remains provenance-verifiable after shred; future reliance is contractual and outside SD revocation,
- DEK/salt regeneration is impossible from stored SD artifacts,
- escrow reveal checks are not affected by SD revocation state.

## §17 - Cross-references

### §17.1 S2-1 imports

S2-7 imports S2-1 §1 conventions, §1.1 HKDF convention for SD salt derivation, §2 tag construction/disjoint namespace discipline, §3 `authorizationId`/`h_commit`/`pda_root`, §4 `commit_AAD`, §6.3 Shamir reconstruction convention as the `file_key` isolation boundary, §6.4 as the closest DEK-as-IKM example where relevant, §16 error redaction, and §17/App. C SD ownership boundary.

### §17.2 S2-2 imports

S2-7 imports S2-2 §0.4 SD scope-out, §1.3 custom-error redaction, §1.5/§16 role names, §9 registry governance shape, App. A `IDisclosureRegistry` minimal shape, and §21.6/§21.16 isolation rule that SD cannot affect escrow reveal authorization.

### §17.3 BP-N back-propagation requests

**BP-SD-1: add SD root binding to S2-1.** CLOSED 2026-05-05. S2-1 `CommitAAD` now includes `sdMerkleRoot: [u8; 32]`, updates field count and byte arithmetic, and sets the SD-disabled value to 32 zero bytes.

**BP-SD-2: list S2-7 SD tags in S2-1 §2/§17.** CLOSED 2026-05-05. S2-1 delegates SD tags to S2-7 and carries the active `TAG_SD_*_V3` family plus the `CEALIS_SD_` prefix rule.

**BP-SD-3: expand S2-2 DisclosureRegistry shape or defer fully to S2-7.** CLOSED 2026-05-05. S2-2 App. A now exposes PLONK proof verification and revocation functions plus SD roles.

### §17.4 Forward references

| Target | Required consumption |
|---|---|
| S2-3 | library pins for Poseidon, PLONK, trusted setup, proof serialization, verifier generator |
| S2-4 | field-mapping UI/API, Claim builder, Mode B rejection |
| S2-5 | onboarding response transport, payload compression, partner auth, error transport |
| S2-6 | proving-key ceremony, verifier deployment, revocation operations, incident response |
| Stage 3 | reference implementation, vectors, conformance report |

## App. A - Per-predicate circuit pseudocode

### A.1 Equality

```
private: value, salt, merkle_path[]
public: authorization_scalar, h_commit, partner, pda, claim, field_set_digest,
        sdMerkleRoot, expected_value, 0, 0, expiry, revocation, verifier_ref, proof_context

commitment = Poseidon5(TAG_SD_FIELD_V3, authorization_scalar, field_id, salt, value)
assert value == expected_value
assert MerkleVerify(commitment, field_id, policy, merkle_path, sdMerkleRoot)
assert Binding(public inputs)
```

### A.2 Non-equality

```
private: value, salt, inv, merkle_path[]
public: forbidden_value, shared binding inputs

commitment = Poseidon5(...)
diff = value - forbidden_value
assert diff * inv == 1
assert MerkleVerify(...)
assert Binding(...)
```

### A.3 Range

```
private: value, salt, value_bits[], merkle_path[]
public: min, max, bit_width, shared binding inputs

commitment = Poseidon5(...)
assert BitsToNum(value_bits) == value
assert value < 2^bit_width
assert value >= min
assert value <= max
assert MerkleVerify(...)
assert Binding(...)
```

### A.4 Inline set membership

```
private: value, salt, selector_bits[set_max], merkle_path[]
public: set_values[set_max], set_length, shared binding inputs

commitment = Poseidon5(...)
assert sum(selector_bits) == 1
assert selected = Σ selector_bits[i] * set_values[i]
assert selected == value
assert all i >= set_length: set_values[i] == 0
assert MerkleVerify(...)
assert Binding(...)
```

### A.5 Merkle set membership

```
private: value, salt, field_merkle_path[], set_merkle_path[], set_member_index
public: set_root, shared binding inputs

commitment = Poseidon5(...)
set_leaf = Poseidon3(TAG_SD_CLAIM_V3, set_member_index, value)
assert MerkleVerifySet(set_leaf, set_merkle_path, set_root)
assert MerkleVerifyField(commitment, field_merkle_path, sdMerkleRoot)
assert Binding(...)
```

## App. B - Test vector placeholders

Stage 3 must fill this appendix with concrete values generated by the reference implementation. Required vector categories:

1. `TAG_SD_*_V3` label-to-digest table.
2. Field id derivation for every field type.
3. Field encoding vectors, including normalization edge cases.
4. HKDF master salt and per-field salt vectors using synthetic DEK.
5. Poseidon commitment vectors for every field type.
6. Merkle root vectors with canonical one-leaf padding, 2, 3, 16, 257, and max-depth leaves.
7. Equality proof vector.
8. Range proof vector.
9. Inline set membership proof vector.
10. Merkle set membership proof vector.
11. Non-equality proof vector.
12. Cleartext opening proof vector.
13. Expired proof rejection vector.
14. Revoked proof rejection vector.
15. Mode B rejection vector.
16. SD failure while escrow commit succeeds vector.

No production implementation may claim S2-7 conformance before these vectors exist and pass in CI.

## App. C - Scope-out enumeration

S2-7 does not cover:

| Item | Owner |
|---|---|
| Escrow `file_key`, AEAD, gate signatures, age envelope | S2-1 |
| ConditionEngine modules, `RevealAuthorized`, ShredRegistry | S2-2 |
| Poseidon/PLONK/proving library pins | S2-3 |
| TEE SDK pins and SD worker attestation implementation | S2-3/S2-6 |
| PDA configurator UX and template library | S2-4 |
| Onboarding HTTP routes and webhook delivery | S2-5 |
| Proving key ceremony and verifier deployment runbook | S2-6 |
| Legal analysis of SD outputs | legal audit / counsel workstream |
| Client-side SD for Mode B | future architecture, out of V2 S2-7 |
| Arbitrary post-commit proof generation | structurally unsupported |
| Fully general predicates over committed data | structurally unsupported; new predicates require new circuits |

S2-7 explicitly owns:

| Item | S2-7 section |
|---|---|
| SD tag namespace | §3 |
| per-field Poseidon commitments | §4 |
| `sdMerkleRoot` construction | §5 |
| predicate semantics | §6 |
| PLONK circuit surfaces | §7 |
| onboarding SD payload semantics | §8 |
| partner SDK verification obligations | §9 |
| on-chain SD verifier shape | §10 |
| proof expiry and revocation | §11 |
| PDA field mapping model | §12 |
| shredding interaction | §13 |
| Mode B incompatibility | §14 |
| asymmetric isolation | §15 |
| test obligations | §16 |

## App. D - Normative algorithms

This appendix restates the core S2-7 algorithms in implementation-oriented form. The pseudocode is normative for ordering, failure boundaries, and data dependencies. Concrete language bindings may differ, but they must be observationally equivalent against the Stage 3 vectors.

### D.1 Build SD plan

Inputs:

- `pda_config`
- `schema`
- `partner_id`
- `claim_configs[]`
- `field_policy_overrides[]`

Output:

- `sd_plan`
- `sd_plan_digest`
- ordered `field_plan[]`
- ordered `claim_plan[]`

Algorithm:

```
function buildSdPlan(pda_config, schema, partner_id, claim_configs, field_policy_overrides):
    if pda_config.sd_enabled == false:
        return disabled plan

    assert pda_config.ingestion_mode == MODE_A
        else ERR_SD_CONFIG_MODE_B_INCOMPATIBLE

    normalized_schema = canonicalize_schema(schema)
    schema_digest = keccak256(normalized_schema.bytes)

    fields = []
    for each declared schema field:
        normalized_path = normalize_field_path(field.path)
        field_path_hash = keccak256(utf8(normalized_path))
        field_type_code = canonical_type_code(field.type)
        field_id = keccak256(
            TAG_SD_FIELD_ID_V3
            || schema_digest
            || field_path_hash
            || field_type_code
        )
        policy = field_policy_overrides.get(field_id, default=escrow_only)
        assert policy in {cleartext, zkp, escrow_only}
            else ERR_SD_FIELD_POLICY_UNKNOWN
        fields.push({ field_id, normalized_path, field_type_code, policy })

    ordered_fields = sort(fields, by field_path_hash, field_type_code, field_id, declaration_index)

    for each claim_config:
        assert every referenced field_id exists
        assert no referenced field has policy escrow_only
        assert claim_config.claim_type in {range, equality, set_membership, non_equality, composed}
        if claim_config.claim_type == composed:
            assert every leaf predicate type in {range, equality, set_membership, non_equality}
        assert expression tree within caps
        claim_ast = canonicalize_claim_ast(claim_config)
        expression_digest = keccak256(SCALE_encode(claim_ast))
        claim_id = keccak256(
            TAG_SD_CLAIM_V3
            || partner_id
            || pda_config.pda_id
            || u64be(pda_config.pda_version)
            || u32be(claim_config.claim_index)
            || expression_digest
        )
        claim_plan.push({ claim_id, expression_digest, claim_ast, verifier_policy })

    sd_plan = SCALE_encode({
        partner_id,
        pda_id,
        pda_version,
        schema_digest,
        ordered_fields_digest,
        claim_plan_digest,
        mode: MODE_A,
        sd_version: "s2-7-1.0"
    })

    sd_plan_digest = keccak256(TAG_SD_PLAN_V3 || sd_plan)
    return { sd_plan, sd_plan_digest, ordered_fields, claim_plan }
```

The configurator must produce the same `sd_plan_digest` as the ingestion TEE. If it does not, the ingestion TEE rejects SD execution and returns SD failure while preserving escrow behavior. This prevents the partner UI from showing one disclosure plan while the TEE executes another.

### D.2 Execute SD during Mode A commit

Inputs:

- plaintext payload,
- escrow commit context,
- SD plan,
- DEK,
- TEE attestation context.

Output:

- SD bundle or SD failure object.

Algorithm:

```
function executeSdAtCommit(plaintext, commit_ctx, sd_plan, DEK, tee_ctx):
    assert commit_ctx.ingestion_mode == MODE_A
        else ERR_SD_CONFIG_MODE_B_INCOMPATIBLE

    status = "complete"
    failures = []
    fatal_sd_error = null
    skip_generation = false
    normalized_payload = null
    sd_master_salt = null
    leaves = []
    field_records = {}
    encoded_values = []
    field_salts = []
    sd_salt_context_digest = null
    proofs = []
    cleartext_outputs = []
    sdMerkleRoot = null
    merkle_paths = {}
    tmpfs_artifacts = []
    witness_buffers = []

    try:
        normalized_payload = canonicalize_payload_against_schema(plaintext, sd_plan.schema)
        if normalized_payload failed:
            fatal_sd_error = { stage: "schema", code: ERR_SD_FIELD_ENCODING_INVALID }
            status = "failed"
            failures.push(fatal_sd_error)
            skip_generation = true

        if !skip_generation:
            sd_salt_context_digest = deriveSdSaltContextDigest(commit_ctx, sd_plan.sd_plan_digest)
            sd_master_salt = deriveSdMasterSalt(DEK, sd_salt_context_digest)
            if sd_master_salt failed:
                fatal_sd_error = { stage: "salt", code: ERR_SD_SALT_DERIVATION_FAIL }
                status = "failed"
                failures.push(fatal_sd_error)
                skip_generation = true

        if !skip_generation:
            for field in sd_plan.ordered_fields:
                value = read_field(normalized_payload, field.normalized_path)
                encoded = encode_field_value(value, field.field_type_code)
                if encoded failed:
                    fatal_sd_error = { field_id: field.field_id, code: ERR_SD_FIELD_ENCODING_INVALID }
                    break
                encoded_values.push(encoded)

                field_salt = deriveSdFieldSalt(
                    sd_master_salt,
                    commit_ctx.authorizationId,
                    field.field_id,
                    field.field_index
                )
                if field_salt failed:
                    fatal_sd_error = { field_id: field.field_id, code: ERR_SD_SALT_DERIVATION_FAIL }
                    break
                field_salts.push(field_salt)

                commitment = Poseidon5(
                    scalar(TAG_SD_FIELD_V3),
                    scalar(commit_ctx.authorizationId),
                    scalar(field.field_id),
                    field_salt,
                    encoded.scalar
                )

                leaf = Poseidon5(
                    scalar(TAG_SD_MERKLE_V3),
                    scalar(field.field_index),
                    scalar(field.field_id),
                    commitment,
                    scalar(policy_code(field.policy))
                )

                leaves.push(leaf)
                field_records[field.field_id] = {
                    encoded,
                    canonical_value: value,
                    commitment,
                    salt: field_salt,
                    policy: field.policy
                }

            if fatal_sd_error != null:
                status = "failed"
                failures.push(fatal_sd_error)
                skip_generation = true

        if !skip_generation:
            sdMerkleRoot, merkle_paths = buildBinaryPoseidonTree(leaves)

            for field in sd_plan.ordered_fields:
                if field.policy == cleartext:
                    record = field_records[field.field_id]
                    if field.cleartext_opening_mode == zk_opened:
                        proof = proveEqualityOpening(record, merkle_paths[field.index], sdMerkleRoot)
                        if proof ok:
                            cleartext_outputs.push({
                                field,
                                value: record.canonical_value,
                                commitment: record.commitment,
                                merkle_path: merkle_paths[field.index],
                                proof
                            })
                        else:
                            status = partial_or_failed(status)
                            failures.push({ field_id: field.field_id, code: ERR_SD_PROOF_INVALID })
                    else if field.cleartext_opening_mode == tee_attested:
                        cleartext_outputs.push({
                            field,
                            value: record.canonical_value,
                            commitment: record.commitment,
                            merkle_path: merkle_paths[field.index],
                            tee_attestation_digest
                        })

            for claim in sd_plan.claim_plan:
                if claim references any missing field_record:
                    status = partial_or_failed(status)
                    failures.push({ claim_id: claim.claim_id, code: ERR_SD_FIELD_ENCODING_INVALID })
                    continue

                proof = proveClaim(claim, field_records, merkle_paths, sdMerkleRoot, commit_ctx)
                if proof ok:
                    proofs.push(proof)
                else:
                    status = partial_or_failed(status)
                    failures.push({ claim_id: claim.claim_id, code: ERR_SD_PROOF_INVALID })

    catch panic:
        status = "failed"
        failures.push({ stage: "panic", code: ERR_SD_ONBOARDING_PARTIAL_FAILURE })
    finally:
        zeroize(plaintext)
        zeroize(normalized_payload)
        zeroize(sd_master_salt)
        zeroize_all(field_salts)
        zeroize_all(encoded_values)
        zeroize_all(field_records[*].salt)
        zeroize_all(field_records[*].encoded)
        zeroize_all(witness_buffers)
        wipe_tmpfs(tmpfs_artifacts)

    if status == "failed" && sdMerkleRoot == null:
        return assembleFailureBundle(commit_ctx, sd_plan.sd_plan_digest, failures)

    sd_bundle_digest = deriveSdBundleDigest(commit_ctx, sdMerkleRoot, sd_salt_context_digest, sd_plan.sd_plan_digest)
    return assembleBundle(status, sdMerkleRoot, sd_salt_context_digest, sd_bundle_digest, cleartext_outputs, proofs, failures)
```

The TEE must route every exit through the finalizer. Plaintext, normalized values, salts, encoded values, witness buffers, and prover tmpfs artifacts are zeroized on success, partial failure, full SD failure, timeout, and panic. A field encoding or salt failure before root construction fails SD as a whole; it must never feed `encoded.scalar`, placeholder salts, placeholder leaves, commitments, proofs, or cleartext outputs. In this valid failure-before-root state, the SD bundle may omit `sdMerkleRoot` while the escrow commit remains valid and carries `commit_AAD.sdMerkleRoot = 0x00...00` only if the PDA records SD as failed before root construction. A fake non-zero root is forbidden. The escrow plaintext zeroization obligation is shared with ingestion and must run even if SD code panics. SD finalization failure is a security incident for S2-6, but it must not invalidate an otherwise valid escrow commit under §15.

### D.3 Build binary Poseidon tree

```
function buildBinaryPoseidonTree(leaves):
    assert len(leaves) > 0
    depth = max(1, ceil_log2(len(leaves)))
    assert 1 <= depth <= 16
    target = 2^depth

    padded = leaves
    for j from len(leaves) to target - 1:
        padded.push(Poseidon5(TAG_SD_MERKLE_V3, j, 0, 0, 0))

    levels = [padded]
    current = padded
    while len(current) > 1:
        next = []
        for i in range(0, len(current), 2):
            next.push(Poseidon3(TAG_SD_MERKLE_V3, current[i], current[i+1]))
        levels.push(next)
        current = next

    root = current[0]
    paths = derive_paths_from_levels(levels)
    return root, paths
```

Path ordering is leaf-to-root. Each path element includes sibling scalar and direction bit. Direction bit `0` means current node is left child; `1` means current node is right child. Circuits must constrain direction bits to boolean values.

### D.4 Verify cleartext field

```
function verifyCleartextField(sd_bundle, cleartext_item, escrow_commit, pda_config):
    assert sd_bundle.partner_id == escrow_commit.partner_id
        else ERR_SD_PARTNER_MISMATCH
    assert sd_bundle.authorizationId == escrow_commit.authorizationId
        else ERR_SD_AUTHORIZATION_MISMATCH

    field_meta = pda_config.field_by_id(cleartext_item.field_id)
    assert field_meta.policy == cleartext
        else ERR_SD_FIELD_POLICY_UNKNOWN

    encoded = encode_field_value(cleartext_item.value, field_meta.field_type_code)
        else ERR_SD_FIELD_ENCODING_INVALID

    assert verifyMerklePath(
        cleartext_item.field_commitment,
        cleartext_item.field_id,
        policy_code(cleartext),
        cleartext_item.merkle_path,
        sd_bundle.sdMerkleRoot
    )
        else ERR_SD_MERKLE_PATH_INVALID

    if cleartext_item.opening_mode == cleartext_zk_opened:
        assert verifyProof(cleartext_item.opening_proof)
            else ERR_SD_PROOF_INVALID
        assert public input expected_value == encoded.scalar
            else ERR_SD_PUBLIC_INPUT_MISMATCH
    else if cleartext_item.opening_mode == cleartext_attested:
        assert verifyTeeAttestation(cleartext_item.cleartext_attestation_digest)
            else ERR_SD_PROOF_INVALID
    else:
        reject
```

The SDK must not reconstruct the field commitment without salt. That is intentional. It verifies either a zero-knowledge opening or a TEE attestation. Any SDK that asks for salts or accepts salts is non-conforming.

### D.5 Verify Claim

```
function verifyClaim(sd_bundle, claim_item, escrow_commit, pda_config, registry_clients, now):
    assert claim_item.expiry_timestamp >= now
        else ERR_SD_CLAIM_EXPIRED

    assert !registry_clients.revocation.isRevoked(claim_item.disclosure_id)
        else ERR_SD_CLAIM_REVOKED

    claim_config = pda_config.claim_by_id(claim_item.claim_id)
    assert claim_config exists
        else ERR_SD_PUBLIC_INPUT_MISMATCH

    expected_public_inputs = buildPublicInputs(
        claim_config,
        sd_bundle,
        escrow_commit,
        claim_item.expiry_timestamp,
        claim_item.disclosure_id,
        claim_item.verifier_ref
    )

    assert claim_item.public_inputs == expected_public_inputs
        else ERR_SD_PUBLIC_INPUT_MISMATCH

    verifier = registry_clients.verifier.getVerifierAt(
        claim_item.verifier_ref,
        escrow_commit.authorizationBlock
    )
        else ERR_SD_PROOF_INVALID

    assert verifier.verifyProof(claim_item.proof, claim_item.public_inputs)
        else ERR_SD_PROOF_INVALID

    return valid
```

Historical verifier lookup uses the generation block of the proof, not current block, when checking whether the verifier existed at generation time. Current deprecation/revocation policy is checked separately. This mirrors S2-2 historical lookup discipline without letting verifier rotation break old proofs.

### D.6 Register disclosure on-chain

On-chain disclosure registration is optional. When used, the registration transaction commits the existence of an SD proof without publishing witness data:

```
disclosure_id = keccak256(
    TAG_SD_COMMIT_V3
    || authorizationId
    || claim_id
    || proof_context_digest
    || proof_digest
)
```

`proof_digest = keccak256(proof_bytes)`. The chain stores `disclosure_id`, `authorizationId`, `claim_id`, `verifier_ref`, `expiry_timestamp`, and `authorizedRevoker`. It does not store public inputs unless the partner explicitly needs public composability; even then, public inputs must be screened for PII-adjacent semantics. A partner who wants on-chain composability should prefer storing a compact `proof_context_digest` and making full public inputs available through a partner-controlled endpoint or IPFS object with clear privacy policy.

### D.7 Recompute SD salt context and bundle digest

```
function deriveSdSaltContextDigest(commit_ctx, sd_plan_digest):
    return keccak256(
        TAG_SD_SALT_CONTEXT_V3
        || commit_ctx.authorizationId
        || commit_ctx.pda_root
        || commit_ctx.schema_digest
        || commit_ctx.partner_id
        || sd_plan_digest
    )

function deriveSdBundleDigest(commit_ctx, sdMerkleRoot, sd_salt_context_digest, sd_plan_digest):
    return keccak256(
        TAG_SD_COMMIT_V3
        || commit_ctx.authorizationId
        || commit_ctx.h_commit
        || commit_ctx.pda_root
        || commit_ctx.partner_id
        || uint256be(sdMerkleRoot)
        || sd_salt_context_digest
        || sd_plan_digest
    )
```

`uint256be(sdMerkleRoot)` is the 32-byte big-endian encoding of the BN254 scalar. It must be `< p`; values outside BN254 field are invalid before digest construction. `deriveSdSaltContextDigest` is intentionally acyclic: it does not consume `sdMerkleRoot`, `commit_AAD`, `aad_digest`, `commit_context_digest`, or final `h_commit`.

## App. E - Security and privacy analysis

### E.1 SD cannot bypass escrow reveal

The primary security property is negative: SD cannot become a second release mechanism. S2-7 enforces that property through six constraints.

First, SD runs at commit time only. It has no route to request gate signatures, no route to call the combiner, and no route to decrypt an age envelope. Second, SD proofs are over field commitments generated while plaintext is already present inside Mode A ingestion; they do not require or imply any reveal ceremony. Third, SD contracts are isolated from ConditionEngine. S2-2 already states that SD verifier state cannot affect escrow reveal authorization, and S2-7 preserves that by making verifier contracts partner/composability surfaces only. Fourth, SD failure is asymmetric: it can fail without blocking escrow, which prevents the SD sidecar from becoming an accidental escrow precondition. Fifth, SD salts are derived one-way from DEK and zeroized, so they do not expose DEK or permit DEK reconstruction. Sixth, Mode B rejects this SD pipeline rather than creating a mixed path where the subject discloses selected plaintext into Cealis while claiming non-custody.

Auditors should test this property by trying to connect every SD output to a reveal path. A valid connection exists only at shared identifiers (`authorizationId`, `h_commit`, `pda_root`, `partner_id`) and current `commit_AAD.sdMerkleRoot` binding. None of those identifiers gives access to the escrow plaintext.

### E.2 Commitment hiding and binding

Per-field commitments are hiding only if salts remain secret. Because salts are TEE-only and never stored, a partner seeing `field_commitment` should not be able to brute-force low-entropy fields directly from the commitment. However, the commitment is not a magic privacy shield. If the field value has a tiny domain and the salt leaks, the value is brute-forceable. If the proof public inputs disclose the predicate tightly enough, the partner learns the predicate's fact. S2-7 therefore treats SD artifacts as confidential partner records.

Binding rests on Poseidon collision resistance in the BN254 field, deterministic field encoding, and deterministic Merkle ordering. An implementation that normalizes strings differently, handles decimals with different scale, orders leaves by JSON order, or uses modulo reduction for salts can break cross-implementation binding. Stage 3 vectors must cover these edge cases because most SD bugs will be canonicalization bugs, not exotic cryptographic failures.

### E.3 Salt derivation threat model

The salt derivation deliberately uses DEK as IKM but does not feed salt material back into escrow. If an attacker obtains all SD salts but not DEK, they may attack SD field privacy but cannot derive the escrow DEK. If an attacker obtains DEK, escrow plaintext is already compromised; SD salt secrecy is no longer the binding risk. If an attacker obtains `sd_master_salt`, they can derive all per-field salts for that commit and brute-force low-entropy committed fields. That is why `sd_master_salt` is handled like sensitive key material inside the TEE.

Deriving salts from DEK rather than independent randomness has two benefits. It makes crypto-shredding semantics coherent: once DEK is gone and plaintext is gone, salts are gone. It also avoids storing a second long-lived SD secret. The cost is that SD salt generation is tied to Mode A's TEE trust boundary. This is acceptable because SD itself already requires that boundary.

### E.4 Low-entropy fields

Many SD fields have low entropy: country, age threshold, boolean residency flags, sanctions-list membership, investor accreditation category, legal entity type. ZK proofs should be read as controlled disclosures of facts, not as proof that "nothing about the field was disclosed." A proof of `age >= 18` discloses that fact. A proof of country membership in `EU` discloses regional status. A non-equality proof against a prohibited jurisdiction discloses not being in that one jurisdiction but may still narrow the set.

PDA templates should avoid pretending low-entropy predicates are privacy-neutral. They are often commercially useful precisely because they disclose enough for onboarding. The right claim is "the partner learns only the configured fact, not the underlying field value." Even that claim depends on set size and predicate shape.

### E.5 Cleartext fields

Cleartext fields are intentionally disclosed. The security goal is not hiding but provenance: the partner can verify that the field came from the same TEE commit process and matches the SD commitment tree. Every UI/API consuming S2-7 should label cleartext outputs plainly. Calling them "selectively disclosed proofs" would blur the line between cleartext and ZK predicates.

For regulated partner flows, cleartext equality openings should use ZK equality proofs by default so the partner does not need to rely solely on an additional TEE signature for provenance. For low-risk operational fields, TEE-attested cleartext can be cheaper and acceptable. The PDA must record which opening mode applies per field.

### E.6 Revocation semantics

Claim-proof revocation is policy invalidation, not cryptographic erasure. The partner may still possess proof bytes. The proof may still verify mathematically. The SDK returns invalid because the revocation registry says the partner should not rely on it. This distinction matters for legal and audit language. "Revoked" does not mean "deleted from all partner systems"; it means "no longer valid for decisions that respect the registry."

Shred-triggered Claim-proof revocation follows the same pattern. Shred blocks future escrow reveals and deletes vault ciphertext; it does not reach into the partner's database and erase proofs already delivered at onboarding. The revocation registry creates the machine-readable signal for partners to stop relying on those Claim proofs. Cleartext values and field commitments already delivered at onboarding are not SD-revocable; only future reliance on them is governed by partner contract, privacy notice, and controller/processor obligations.

### E.7 On-chain privacy

On-chain verifier use should be rare and explicit. Publishing public inputs may reveal partner, PDA, authorization, field-set, predicate bounds, expiry, and revocation identifiers. Even when no plaintext value appears, the combination can be sensitive. S2-7 therefore separates pure proof verification from `verifyAndCommitDisclosure` policy functions. Partners needing private onboarding should verify off-chain and store only local audit records.

If a partner insists on on-chain verification, the PDA should classify the Claim as public-verifiable during configuration. The configurator should show which public inputs will be visible and require partner acknowledgement. This is S2-4 UI detail, but the normative data distinction lives here.

### E.8 TEE compromise

If the Mode A SD TEE is compromised during commit, plaintext and SD salts can leak. S2-7 does not claim to defend fully against that. The mitigation is the same Mode A trust chain as ingestion: published source, reproducible build, on-chain binary/measurement registry, runtime attestation, vendor trust, compiler/toolchain trust, and external audit. SD does not improve that trust chain; it consumes it.

This is also why Mode B rejection is strict. Mode B exists for use cases where the Mode A plaintext-in-TEE trust chain is unacceptable. Adding TEE-side SD to Mode B would destroy the thing Mode B is for.

### E.9 Malicious partner

A partner can misuse cleartext fields it legitimately receives, can share proofs with another party, can ignore Claim-proof revocation, or can make business decisions from expired Claim proofs. Cryptography cannot prevent a partner from misusing data already disclosed to it. S2-7 mitigates replay through partner binding, Claim-proof expiry, Claim-proof revocation, and SDK policy checks. Legal contracts and partner governance handle misuse outside the protocol.

The partner binding means a proof generated for Partner A should not verify as a proof for Partner B. It does not mean Partner A cannot show the proof to Partner B as evidence. If that matters, the Claim should include audience-specific language in the partner contract and the SDK output should display the bound partner id.

### E.10 Malicious subject

A subject can provide false plaintext if the PDA permits self-declared fields. SD proves predicates about the committed plaintext, not truth in the real world. External truth comes from Issuer/attestation inputs and PDA schema policy. A proof that "declared income >= X" is not the same as a proof from a bank issuer unless the field is backed by an issuer attestation. PDA templates must distinguish self-declared and externally attested fields in their Claim labels.

### E.11 Circuit soundness failure

If a circuit is unsound, a false proof may verify. Mitigations:

- small circuit families,
- versioned verifier refs,
- fixed public input order,
- published vectors,
- external audit before production,
- deprecation and revocation path,
- partner SDK refusing deprecated verifier refs for new proofs.

An unsound verifier incident should trigger verifier deprecation plus revocation of proofs generated under affected verifier refs where the false-proof risk is material. S2-6 owns the incident runbook.

### E.12 Proving key compromise

PLONK proving keys are not normally secret in the same way as witness data, but toxic waste from trusted setup would be catastrophic if retained. S2-6 must verify the universal setup transcript and prove that circuit-specific keys derive from it. S2-7 requires verifier metadata to name setup transcript digest and verification-key digest so auditors can trace a deployed verifier back to a ceremony.

### E.13 Canonicalization attacks

Canonicalization attacks are the most likely practical failures:

- Unicode composed vs decomposed forms,
- country code case differences,
- decimal scale mismatch,
- timezone/date conversion,
- array ordering,
- nullable field semantics,
- enum ordinal drift after schema update,
- address checksum formatting,
- object hash computed over non-canonical JSON.

S2-7's response is to put canonicalization before commitment and to bind schema digest, field type, and field path into `field_id`. Stage 3 must include adversarial fixtures for every item above.

### E.14 Public-input substitution

An attacker may take a valid proof and attach it to a different Claim or bundle. This is blocked by public-input binding. The verifier checks the proof against public inputs, and the SDK recomputes public inputs from received context rather than trusting the serialized array. If serialized public inputs differ from recomputed public inputs, verification fails before proof verification.

### E.15 Merkle path substitution

An attacker may take a field commitment from one tree and present it under another root. This is blocked by Merkle path verification plus Claim binding to `sdMerkleRoot`; S2-1 now also AEAD-binds that root through `commit_AAD.sdMerkleRoot`.

## App. F - Auditor conformance matrix

The conformance matrix below gives auditors and Stage 3 implementers a direct checklist. A Stage 3 conformance report should add columns for implementation file, test file, vector id, and residual risk.

| ID | Requirement | Spec anchor | Failure if absent |
|---|---|---|---|
| SD-CFG-001 | Mode B + SD rejected in configurator and API | §14 | Mode B trust claim collapses |
| SD-CFG-002 | New fields default to `escrow_only` | §12.4 | partner receives unintended data |
| SD-CFG-003 | Claim references cannot target `escrow_only` fields | §7.4/§12 | hidden disclosure path |
| SD-CFG-004 | Claim expression trees bounded | §6.6 | unbounded proving/verification |
| SD-CFG-005 | SD plan digest deterministic | App. D.1 | UI/TEE plan drift |
| SD-TEE-001 | SD runs inside Mode A TEE boundary | §2.2 | plaintext leaves attested boundary |
| SD-TEE-002 | SD failure does not block escrow | §15 | sidecar becomes escrow precondition |
| SD-TEE-003 | plaintext and normalized payload zeroized on every exit path | §2.6/App. D.2 | post-commit proof/data leak |
| SD-TEE-004 | salts zeroized and never logged | §2.5/§1.4/App. D.2 | commitment privacy failure |
| SD-TEE-005 | witness buffers and prover tmpfs artifacts not persisted | §7.4/App. D.2 | proof privacy failure |
| SD-TEE-006 | field encoding failure never feeds commitments/proofs | App. D.2 | invalid field state becomes committed |
| SD-TAG-001 | all active tags use `CEALIS_SD_` namespace | §3 | cross-namespace collision risk |
| SD-TAG-002 | tag digests self-tested | §16.1 | domain separation drift |
| SD-FIELD-001 | field ids bind schema digest/path/type | §1.1 | schema substitution |
| SD-FIELD-002 | canonical field encoding implemented | §4.2 | cross-client mismatch |
| SD-FIELD-003 | nullable semantics explicit | §4.2 | absence/value ambiguity |
| SD-FIELD-004 | field salts use rejection sampling | §2.4 | salt scalar bias/collision |
| SD-COM-001 | per-field Poseidon commitment order matches §4.1 | §4.1 | invalid vectors/proofs |
| SD-COM-002 | commitments stored without salts | §4.5 | salt leakage |
| SD-MERKLE-001 | leaf ordering deterministic | §5.3 | partner recompute failure |
| SD-MERKLE-002 | padding leaf formula implemented | §5.2 | root mismatch |
| SD-MERKLE-003 | paths include direction bits | App. D.3 | ambiguous Merkle verification |
| SD-MERKLE-004 | `escrow_only` leaves included where plan requires | §5.1 | omitted-field ambiguity |
| SD-BIND-001 | SDK detects `commit_AAD` vs reference binding | §5.5 | overclaimed root binding |
| SD-BIND-002 | `commit_AAD.sdMerkleRoot` verified against bundle root | §5.5/§17.3 | inaccurate audit/public copy |
| SD-PRED-001 | range circuit checks bit width | §6.2 | overflow/range bypass |
| SD-PRED-002 | equality circuit checks exact scalar | §6.3 | false equality proof |
| SD-PRED-003 | set membership binds configured set | §6.4 | set substitution |
| SD-PRED-004 | non-equality uses inverse witness | §6.5 | zero-diff bypass |
| SD-PRED-005 | composition bounded and deterministic | §6.6 | verifier ambiguity |
| SD-PLONK-001 | verifier refs bind verification key and public schema | §7.1 | wrong verifier accepted |
| SD-PLONK-002 | public input order fixed | §7.6 | proof substitution |
| SD-PLONK-003 | off-chain SDK rejects proofs on-chain verifier rejects | §7.7 | SDK/chain split |
| SD-PLONK-004 | circuit versions append-only | §7.8 | old proofs broken |
| SD-PLONK-005 | constraint budgets measured | §7.9 | unbounded operations |
| SD-API-001 | onboarding response includes binding level | §8.1 | partner unaware of weaker binding |
| SD-API-002 | cleartext opening mode explicit | §8.1/§9.4 | partner trust confusion |
| SD-API-003 | partial SD status represented | §7.5/§8 | silent proof loss |
| SD-SDK-001 | SDK recomputes public inputs | App. D.5 | public-input substitution |
| SD-SDK-002 | SDK checks expiry | §11.1 | stale proof accepted |
| SD-SDK-003 | SDK checks Claim-proof revocation | §11.4 | revoked Claim proof accepted |
| SD-SDK-004 | SDK returns machine-readable rejected items | §9.1 | caller cannot handle partials |
| SD-SDK-005 | SDK labels trust mode for cleartext | §9.4 | TEE-attested vs ZK-opened confusion |
| SD-CHAIN-001 | on-chain verification optional | §10.3 | SD state blocks escrow/commercial flow |
| SD-CHAIN-002 | verifier contracts store no plaintext/salts/witnesses | §10.1 | on-chain privacy leak |
| SD-CHAIN-003 | revocation registry isolated from ConditionEngine | §11.2 | SD affects reveal authorization |
| SD-CHAIN-004 | disclosure registration stores digests only by default | App. D.6 | public-input privacy leak |
| SD-SHRED-001 | shred enqueues SD revocation | §13.4 | stale claims survive policy |
| SD-SHRED-002 | shred does not pretend to erase partner-held proofs | §13.3/App. E.6 | legal overclaim |
| SD-SHRED-003 | no post-shred proof generation API | §13.2 | crypto-shred semantics broken |
| SD-TEST-001 | vectors cover every field type | §16/App. B | canonicalization bugs missed |
| SD-TEST-002 | vectors cover every predicate | §16/App. B | circuit bugs missed |
| SD-TEST-003 | vectors cover Mode B rejection | §16/App. B | incompatible mode slips |
| SD-TEST-004 | vectors cover SD fail + escrow success | §16/App. B | isolation untested |

## App. G - Partner integration profiles

This appendix is not a product-tier system. It is a practical mapping of partner verification posture to the same SD primitives. The protocol surface is the same; the partner decides how much verification to perform and which Claims to require. The `regulated` and `B2B` labels below are SD delivery profiles, not PDA trust tiers.

### G.1 Strict regulated SD delivery profile

Use when SD output affects credit, legal, medical, regulated financial onboarding, or any partner process where a false proof creates material legal exposure.

Requirements:

- Mode A Phase 2 TEE only.
- `rootBindingLevel = commit_AAD`;
- every cleartext field uses `cleartext_zk_opened`;
- no TEE-attested-only cleartext openings;
- all proofs checked off-chain by SDK;
- verifier registry checked online;
- revocation checked online;
- no offline grace;
- proof expiry short enough for field volatility;
- partner stores verification transcript hash;
- partner does not publish public inputs on-chain unless PDA marks Claim public-verifiable.

Residual risk statement: the partner trusts the Mode A TEE chain during commit and the circuit/verifier stack. The partner does not trust Cealis for post-commit proof generation because none exists.

### G.2 Standard B2B SD delivery profile

Use for typical partner onboarding where SD proofs reduce data exposure but are not themselves the sole legal decision basis.

Requirements:

- Mode A;
- Phase 2 preferred for partner-ready deployments;
- cleartext fields may use ZK opening or TEE-attested opening per PDA;
- SDK verification mandatory;
- revocation checked online with short retry window;
- proof expiry based on business need;
- partial SD response may be accepted if required Claims pass.

Residual risk statement: partner receives selected cleartext by design and must protect it under its own controller/processor obligations.

### G.3 Low-risk operational profile

Use for non-sensitive operational flags, sandbox integrations, or internal demos that still need to exercise real protocol mechanics.

Requirements:

- synthetic or low-risk data only if Phase 1 is used;
- SDK verification still mandatory;
- TEE-attested cleartext openings permitted;
- offline revocation grace permitted;
- on-chain verification not required;
- no public claim that this profile is regulated-grade.

This profile exists to test and integrate without weakening the production spec. It must not be used as the basis for legal/evidentiary claims.

### G.4 Public-composability profile

Use when a partner wants to make an SD proof consumable by another on-chain protocol.

Requirements:

- PDA marks Claim as public-verifiable;
- public inputs reviewed for privacy leakage;
- on-chain verifier ref registered and active;
- revocation registry checked by consuming protocol;
- expiry enforced on-chain;
- disclosure registration emits digest refs, not plaintext;
- partner accepts that public metadata may reveal business relationship and predicate facts.

Public composability should be the exception. Most SD value is partner-private onboarding, not public proof publication.

## App. H - Stage 3 implementation handoff

### H.1 First milestone: deterministic data model

Implement schema canonicalization, field id derivation, field ordering, field encoding, Claim canonicalization, and `sd_plan_digest`. No circuits should be implemented until this layer has vectors. If this layer drifts, every proof layer above it becomes unreviewable.

Deliverables:

- `sd-plan.test.ts`,
- field encoding vector JSON,
- schema canonicalization fixtures,
- negative tests for path/type/nullable drift.

### H.2 Second milestone: commitment and Merkle library

Implement Poseidon wrappers, salt derivation against synthetic DEKs, per-field commitments, leaf construction, tree building, path generation, and path verification.

Deliverables:

- `sd-commitment.test.ts`,
- Poseidon vector JSON,
- Merkle root/path vector JSON,
- negative tests for ordering, padding, direction bits, and policy-code mismatch.

### H.3 Third milestone: circuits

Implement equality, non-equality, range, inline set, and Merkle set circuits. Start with small depth fixtures, then max-depth fixtures. Keep public input order identical across circuits where §7.6 says so.

Deliverables:

- circuit source files,
- witness generator tests using synthetic data,
- valid and invalid proof fixtures,
- constraint count report,
- verifier key digest report.

### H.4 Fourth milestone: verifier registry and Solidity surface

Implement verifier contracts or adapters, disclosure registry, revocation registry, and verifier-ref resolution. Confirm no contract path touches ConditionEngine reveal authorization.

Deliverables:

- Foundry compile,
- verifier gas snapshots,
- revocation tests,
- UUPS/role tests if registries are upgradeable,
- negative test proving SD revocation does not affect `RevealAuthorized`.

### H.5 Fifth milestone: partner SDK

Implement `verifySdBundle`, field verification, Claim verification, expiry/revocation clients, binding-level output, and profile-specific policies.

Deliverables:

- SDK unit tests,
- bundle fixture tests,
- browser compatibility check for partner integrations,
- error redaction tests,
- profile policy tests.

### H.6 Sixth milestone: end-to-end Mode A onboarding

Run synthetic Mode A ingestion through escrow + SD. Induce SD failures at every stage and prove escrow commits still complete. Induce escrow failures and prove SD output is not emitted for an invalid commit context.

Deliverables:

- end-to-end test report,
- conformance matrix filled against App. F,
- residual risk list,
- BP-SD-1 status note,
- Stage 3 readiness recommendation.

## App. I - Normative data structures

This appendix gives the data structures that Stage 3 should use as the starting point for TypeScript types, Rust structs, JSON schemas, and Solidity-facing ABI structs. S2-5 may wrap these structures in HTTP envelopes, pagination objects, compression formats, or partner-auth metadata, but it must preserve the semantics and required fields.

### I.1 `SdPlan`

`SdPlan` is the compiled disclosure plan emitted by the configurator and re-derived by ingestion.

```scale
struct SdPlan {
  sd_version:                         u16,       // 0x0001 for S2-7 initial release
  partner_id:                         [u8; 32],
  pda_id:                             [u8; 32],
  pda_version:                        u64,
  schema_digest:                      [u8; 32],
  ingestion_mode:                     u8,        // must be 0x01 Mode A when sd_enabled = true
  sd_enabled:                         bool,
  field_policy_root:                  [u8; 32],
  claim_plan_root:                    [u8; 32],
  default_expiry_policy_ref:          [u8; 32],
  revocation_policy_ref:              [u8; 32],
  cleartext_attestation_allowed:      bool,
  public_composability_allowed:       bool
}
```

`field_policy_root` is a Merkle root over ordered `SdFieldPolicy` records. `claim_plan_root` is a Merkle root over ordered `SdClaimConfig` records. `default_expiry_policy_ref` and `revocation_policy_ref` are Claim-proof policy references resolved by S2-4 and S2-6; they are opaque to circuits but bound into `sd_plan_digest`.

`cleartext_attestation_allowed = false` forces every cleartext field to carry a ZK equality opening. `public_composability_allowed = true` is required before any Claim proof may be registered on-chain with public inputs or advertised as public-verifiable.

### I.2 `SdFieldPolicy`

```scale
struct SdFieldPolicy {
  field_index:                        u32,
  field_id:                           [u8; 32],
  field_path_hash:                    [u8; 32],
  field_type_code:                    u8,
  policy:                             u8,        // 1 cleartext, 2 zkp, 3 escrow_only
  nullable:                           bool,
  max_byte_length:                    u32,
  numeric_bit_width:                  u16,
  decimal_scale:                      u8,
  allowed_claim_ids_root:             [u8; 32],
  cleartext_opening_mode:             u8,        // 0 none, 1 zk_opened, 2 tee_attested
  pii_class:                          u8         // 0 none, 1 ordinary, 2 special_category, 3 financial, 4 legal
}
```

`pii_class` is metadata for logging and partner-handling policy. It is not a circuit input unless a Claim explicitly proves a policy property. A field marked `special_category`, `financial`, or `legal` should default to `zkp` or `escrow_only`; `cleartext` requires explicit partner acknowledgement in S2-4.

`numeric_bit_width` is required for range proofs over integer-like fields. For non-numeric fields it is zero. `decimal_scale` is required for `decimal_fixed`; for other types it is zero. `max_byte_length` applies before hashing strings/bytes to field elements and prevents unbounded TEE memory consumption.

### I.3 `SdClaimConfig`

```scale
struct SdClaimConfig {
  claim_index:                        u32,
  claim_id:                           [u8; 32],
  claim_type:                         u8,        // 1 range, 2 equality, 3 set, 4 non_equality, 5 composed
  expression_digest:                  [u8; 32],
  field_ids_root:                     [u8; 32],
  verifier_policy_ref:                [u8; 32],
  expiry_seconds:                     u64,
  public_verifiable:                  bool,
  on_chain_registration_required:     bool,
  revocation_required:                bool,
  partner_decision_critical:          bool
}
```

`partner_decision_critical` means partner onboarding should fail if this Claim fails verification. This flag is not an escrow property. It exists so S2-5 and partner SDKs can report `partial` SD status while still telling the partner application whether its configured onboarding gate passed.

`public_verifiable` means proof public inputs may be published beyond the partner. This flag must be false unless `SdPlan.public_composability_allowed = true`.

`revocation_required` is a Claim-proof policy flag. It does not create field-commitment or cleartext-output revocation handles.

### I.4 `SdBundle`

```typescript
type SdBundle = {
  sd_version: "s2-7-1.0";
  status: "complete" | "partial" | "failed" | "not_configured";
  authorizationId: Hex32;
  h_commit: Hex32;
  pda_root: Hex32;
  partner_id: Hex32;
  pda_id: Hex32;
  pda_version: string;
  schema_digest: Hex32;
  sdMerkleRoot?: HexScalar;
  sd_salt_context_digest: Hex32;
  sd_plan_digest: Hex32;
  sd_bundle_digest: Hex32;
  rootBindingLevel: "commit_AAD";
  generated_at: string;
  tee_attestation_ref?: Hex32;
  cleartext: SdCleartextItem[];
  claims: SdClaimItem[];
  failures: SdFailureItem[];
};
```

`tee_attestation_ref` is optional because co-located G4 ingestion attestation may already be referenced in the escrow onboarding object. A distinct SD TEE remains future/non-conforming until §2.2's required channel and ceremony rules exist; if that future design is adopted, this field becomes mandatory and points to the SD TEE attestation object.

`status = failed` must still include `authorizationId`, `h_commit` if available, `pda_root`, `partner_id`, `pda_id`, `schema_digest`, `sd_plan_digest`, and failures. It must not include partial witnesses or salts. `status = not_configured` must not include fake roots or fake proofs.

### I.5 `SdCleartextItem`

```typescript
type SdCleartextItem = {
  field_id: Hex32;
  field_path_hash: Hex32;
  field_path_label?: string;
  field_type_code: number;
  value_encoding: string;
  value: unknown;
  field_commitment: HexScalar;
  policy_code: 1;
  merkle_path: SdMerklePathElement[];
  opening_mode: "cleartext_zk_opened" | "cleartext_attested";
  opening_proof?: SdProof;
  cleartext_attestation_digest?: Hex32;
};
```

`field_path_label` is optional and may be omitted in high-privacy partner modes. It is never used for cryptographic verification. `value` must be serialized according to S2-5 canonical JSON rules for the declared encoding. A partner SDK must verify the encoded scalar, not rely on JavaScript runtime type inference.

`SdCleartextItem` intentionally has no `expiry_timestamp` or `disclosure_id`. Cleartext delivery is not SD-revocable after the partner receives it; the SDK verifies provenance and opening correctness only.

### I.6 `SdClaimItem`

```typescript
type SdClaimItem = {
  claim_id: Hex32;
  claim_type: "range" | "equality" | "set_membership" | "non_equality" | "composed";
  field_ids: Hex32[];
  verifier_ref: Hex32;
  proof: Hex;
  public_inputs: string[];
  proof_context_digest: Hex32;
  expiry_timestamp: number;
  disclosure_id: Hex32;
  on_chain_registered: boolean;
};
```

`public_inputs` are decimal strings for BN254 scalar values to avoid JSON number precision loss. SDKs may expose BigInt wrappers but wire JSON must not use JavaScript numbers for field elements. `disclosure_id` is a Claim-proof policy handle, not a field-commitment or cleartext-output handle.

### I.7 `SdFailureItem`

```typescript
type SdFailureItem = {
  scope: "bundle" | "field" | "claim" | "registry" | "mode" | "prover" | "verifier";
  field_id?: Hex32;
  claim_id?: Hex32;
  error: SdErrorCode;
  retryable: boolean;
  detail_ref?: Hex32;
};
```

`detail_ref` is a digest or encrypted diagnostic ref. It must never be raw plaintext, raw witness, raw salt, raw proof transcript, or stack trace containing PII. `retryable = true` means a fresh commit or registry retry may work; it does not mean Cealis can regenerate proofs for an existing commit after plaintext destruction.

### I.8 `SdMerklePathElement`

```typescript
type SdMerklePathElement = {
  sibling: HexScalar;
  direction: 0 | 1;
};
```

The array is ordered leaf-to-root. `direction = 0` means the current node is left child and sibling is right child. `direction = 1` means current node is right child and sibling is left child. This convention is circuit-visible and SDK-visible.

### I.9 `SdProof`

```typescript
type SdProof = {
  proof_system: "plonk-bn254";
  verifier_ref: Hex32;
  proof: Hex;
  public_inputs: string[];
  public_input_schema_digest: Hex32;
};
```

The SDK must verify `public_input_schema_digest` against the verifier registry entry before calling proof verification. A proof generated under the right verifier but serialized with the wrong public-input schema must fail before cryptographic verification.

### I.10 `SdVerifierRegistryEntry`

```scale
struct SdVerifierRegistryEntry {
  verifier_ref:                       [u8; 32],
  circuit_family_id:                  [u8; 32],
  circuit_version:                    u32,
  verifier_contract:                  [u8; 20],
  verification_key_digest:            [u8; 32],
  proving_key_digest:                 [u8; 32],
  setup_transcript_digest:            [u8; 32],
  public_input_schema_digest:         [u8; 32],
  max_tree_depth:                     u8,
  max_public_inputs:                  u16,
  effective_block:                    u64,
  tombstone_block:                    u64,
  deprecation_flag_digest:            [u8; 32]
}
```

The registry entry stores digests, not proving keys or verification keys. Full artifacts are distributed through S2-6-controlled artifact channels. `verifier_contract` may be zero for off-chain-only verifier refs; partner SDKs can still resolve verification keys off-chain through S2-3/S2-6 metadata.

### I.11 `SdRevocationRecord`

```scale
struct SdRevocationRecord {
  disclosure_id:                      [u8; 32],
  authorizationId:                    [u8; 32],
  partner_id:                         [u8; 32],
  claim_id:                           [u8; 32],
  subject_commitment_v3:              [u8; 32],
  authorized_revoker:                 [u8; 20],
  revoked:                            bool,
  reason_code:                        u8,
  evidence_ref:                       [u8; 32],
  revoked_at_block:                   u64,
  revoked_at_timestamp:               u64
}
```

`subject_commitment_v3` is pseudonymous but still treated as personal-data-adjacent in partner contexts. Events may include it only if the PDA marks revocation records as partner-private or if the value is already visible through the associated escrow context. The default event indexes `disclosure_id`, `authorizationId`, and `claim_id` per §11.2 — never `subject_commitment_v3`.

`SdRevocationRecord` is claim-shaped by design. It records policy invalidation for Claim proofs and registered disclosure ids. It is not a field-commitment revocation record and does not revoke cleartext outputs already delivered to a partner.

## App. J - BP-SD-1 closed-state discipline

BP-SD-1 is closed by the 2026-05-05 S2-1 backprop patch. S2-1 `CommitAAD` includes:

```scale
sdMerkleRoot: [u8; 32]
```

The field is encoded as 32-byte big-endian scalar bytes at the S2-1 boundary. SD-disabled PDAs set it to 32 zero bytes. SD-enabled PDAs that complete root construction MUST use a non-zero root and MUST match the root in the SD bundle. If SD fails before root construction, escrow remains valid under asymmetric isolation and the SD bundle records `status = "failed"` with no fake root; partner onboarding can fail at the app layer, but escrow finalization does not roll back.

### J.1 SDK behavior for `commit_version = 0x0302`

SDKs implement two active modes for current commits:

| Mode | Detection | Behavior |
|---|---|---|
| `sd_disabled` | `commit_AAD.sdMerkleRoot == 0x00...00` and PDA says SD disabled | accept absence of SD bundle |
| `sd_enabled` | `commit_AAD.sdMerkleRoot != 0x00...00` | require equality with bundle `sdMerkleRoot` |
| `sd_failed_before_root` | `commit_AAD.sdMerkleRoot == 0x00...00`, PDA says SD enabled, and onboarding response has `status = "failed"` with failure stage before root construction | escrow remains valid; partner SDK rejects SD outputs and reports SD failure, not escrow failure |

Any S2-1 `commit_version = 0x0302` commit without the field is invalid. SDKs infer behavior from commit schema/version metadata, not document dates.

### J.2 Historical/pre-`0x0301` compatibility

Pre-`0x0301` fixtures may expose `rootBindingLevel = "sd_bundle_reference"` for archival verification only. That mode means the SD bundle references `authorizationId`, `h_commit`, `pda_root`, and `partner_id`, but the SD root is not AEAD-bound through `commit_AAD.sdMerkleRoot`. It is non-conforming for new partner commits and must not appear in active S2-7 payloads, SDK result types, or regulated/B2B delivery profiles. Active `0x0302` production code must never use `sd_bundle_reference` as a fallback after SD failure.

### J.3 Auditor acceptance criteria

Auditors should see:

1. S2-1 `commit_AAD` field-count and byte-count arithmetic including `sdMerkleRoot`.
2. S2-1 and S2-7 test vectors for SD-enabled and SD-disabled commits.
3. Negative test where bundle root differs from `commit_AAD.sdMerkleRoot`.
4. Negative test where SD disabled uses non-zero root.
5. Public-copy lint rule allowing "AEAD-bound SD root" only for `commit_version = 0x0302` or later.

### J.4 Source-of-truth boundary

S2-1 is canonical for escrow byte layout. S2-7 owns SD root construction and proof semantics. Future SD root shape changes must still propagate through S2-1 before any implementation claims escrow-AEAD binding.

## App. K - Glossary

**Cleartext field.** A field intentionally delivered to the partner at onboarding. It is not hidden. S2-7 gives it provenance through commitments and opening proofs/attestations.

**Claim.** A partner-configured predicate statement over one or more fields, proven at onboarding through a PLONK proof.

**Commit-time.** The one window where plaintext exists inside Mode A ingestion. SD runs here or not at all.

**Disclosure id.** Optional on-chain identifier for a registered SD proof. It is not an escrow reveal id.

**Escrow-only field.** A field that is committed into escrow but not disclosed through SD output.

**Field commitment.** Poseidon commitment to one canonical field value and one TEE-only salt.

**Field id.** Domain-separated identifier derived from schema digest, normalized field path, and type code.

**Mode A.** TEE-ingest mode. Plaintext enters Cealis TEE boundary; SD can run.

**Mode B.** Device-encrypt mode. Plaintext never enters Cealis infrastructure; this S2-7 SD pipeline cannot run.

**Opening proof.** A proof that a cleartext value matches a field commitment without revealing the salt.

**Proof expiry.** Timestamp after which a proof is no longer accepted by policy even if cryptographically valid.

**Revocation id.** Identifier checked against the SD revocation registry to determine whether a proof remains acceptable.

**SD bundle.** Partner onboarding artifact containing SD root, cleartext outputs, Claim proofs, Merkle paths, binding metadata, expiry, and revocation refs.

**SD plan.** Deterministic compiled field-mapping and Claim configuration for a PDA/partner/schema.

**SD root.** `sdMerkleRoot`, the Poseidon Merkle root of SD field commitments.

**Escrow-bound SD root.** S2-1 0x0302 state where `sdMerkleRoot` sits inside `commit_AAD`, affects `aad_digest`, and therefore affects `h_commit`.

**Witness.** Private circuit input: field value, salt, Merkle path internals, range bits, set-membership path, or inverse witness.

## App. L - Seven-view trace

This appendix records the Rule 26 seven-view pass for the SD specification. It is not a replacement for the normative sections; it is an audit aid that shows why the SD design is not allowed to collapse into a single-view answer.

### L.1 Enforcement view

From the Enforcement view, the critical question is whether SD weakens the release condition. It does not. ConditionEngine remains the only on-chain path to `RevealAuthorized`; G2/G3/G4 still provide V3-custody gate authorizations; the combiner reconstructs `file_key` only from threshold Shamir shares after σ verification; SD verifier contracts have no authority to emit reveal events or satisfy custody gates. A partner may use SD proofs to onboard a user or decide whether to enter a relationship, but that is business logic before any enforcement event. It is not release authorization.

The most important negative test for this view is simple: revoke every SD proof and confirm a valid escrow reveal still works when the predefined condition fires; then make every SD proof valid and confirm no escrow reveal works before the predefined condition fires. Both must hold.

### L.2 Tamper-proof view

From the Tamper-proof view, SD adds provenance for onboarding facts. A partner receiving a cleartext country code or an age predicate can verify that the artifact is tied to the same commit context, the same PDA, the same partner, the same schema, and the same SD plan. The SD Merkle root and proof context prevent a partner or attacker from swapping field commitments between bundles without detection.

The BP-SD-1 backprop matters most in this view. With `sdMerkleRoot` inside `commit_AAD`, SD has internal tamper-evidence, explicit reference binding to escrow identifiers, and escrow AEAD binding. Root drift changes `commit_AAD`, `aad_digest`, and therefore `h_commit`.

### L.3 Selective-disclosure view

From the SD view, the design goal is useful onboarding output with minimum necessary disclosure. The field policy triad gives the partner exactly three states to reason about: receive value, receive proof, or receive nothing through SD. The four predicate families cover the first needed surface without implying arbitrary computation over committed data. Composition is bounded because unbounded predicate systems become hard to audit and easy to misrepresent.

The SD view also forces honest language. A cleartext field is not private. A proof discloses the fact it proves. A low-entropy predicate may reveal more than a casual reader expects. The right engineering answer is not to call every output "zero knowledge"; it is to label each output class precisely.

### L.4 Commercial view

From the Commercial view, SD gives partners day-one utility. They do not need to wait for a default/reveal event to get the onboarding facts they need. That makes Cealis usable as partner infrastructure rather than only as a future enforcement artifact. The design keeps cost proportional: partners can request only the fields and predicates needed for their workflow; on-chain verification remains optional; low-risk profiles can use TEE-attested cleartext where ZK opening cost is not justified.

The commercial trap is making SD a mandatory blocker for escrow commit. S2-7 rejects that. A proof-generation outage should not make the custody system unavailable. Partners can reject onboarding at their app layer if their required proofs failed, but the escrow infrastructure should not mutate its security semantics because a side pipeline was slow.

### L.5 Legal view

From the Legal view, SD outputs are data processing events. Cleartext fields are personal data when the field is personal data. Proof public inputs may also be personal-data-adjacent. Revocation is not erasure of partner-held proof bytes; it is a validity signal. Shred blocks future escrow reveal and makes retroactive proof generation impossible, but it does not magically delete what a partner already received.

This view is why S2-7 has explicit PII statements, logging bans, revocation semantics, expiry, and profile distinctions. It also explains why Mode B incompatibility must be strict. If a use case chooses Mode B for commit-time non-custody, routing selected plaintext back through Cealis for SD would be legally and architecturally misleading.

### L.6 Use-case-flex view

From the Use-case-flex view, SD cannot be hard-coded to identity/KYC. The schema and field-id derivation are data-agnostic. A field can be age, jurisdiction, document hash, legal entity category, medical consent flag, source-code license status, M&A closing condition, or archival metadata. The same predicate families apply across those schemas as long as encoding and Claim configuration are explicit.

The spec therefore avoids naming one schema as canonical. It gives field typing, field mapping, Claim binding, and verifier versioning as primitives. New use cases should land by schema and PDA configuration, not by forking SD.

### L.7 Partner-fit view

From the Partner-fit view, partners need different verification postures. A regulated lender may require Phase 2, ZK-opened cleartext, online revocation checks, and commit_AAD-root binding. A sandbox partner may only need SDK verification against synthetic data. A public composability partner may need on-chain verifier contracts but must accept the privacy cost of public inputs.

S2-7 therefore defines integration profiles without making them product tiers. The protocol remains one system. The profile is a verification posture selected by partner need and PDA policy. This keeps partner conversations honest: Cealis can map primitives to their case without claiming every partner needs the same disclosure surface.

## App. M - Public and internal wording constraints

S2-7 is a technical spec, but wording constraints matter because SD is easy to overclaim. Any downstream public copy, partner deck, onboarding docs, or grant material that mentions SD should follow these constraints.

### M.1 Allowed phrasings

Allowed:

- "SD outputs are generated at commit time, before any reveal event."
- "The partner receives configured cleartext fields or proofs, not arbitrary access to escrowed data."
- "SD is parallel to escrow and does not change the release condition."
- "Mode B is incompatible with this TEE-side SD pipeline."
- "Proofs remain mathematically verifiable after delivery, but expiry and revocation decide whether they should still be relied on."
- "Cleartext fields are disclosed by design."
- "A proof reveals the configured fact, not the underlying field value."
- "Post-commit proof generation requires a fresh commit."

### M.2 Banned phrasings

Banned:

- "SD partially unlocks the escrow."
- "The partner can later ask for new proofs from the committed data."
- "ZK means the partner learns nothing."
- "Cleartext SD is private."
- "Mode B supports the same SD flow."
- "Revocation deletes partner-held proofs."
- "SD proof validity is the same as real-world truth."
- "On-chain proof verification is required for escrow security."
- "The SD root is AEAD-bound" for any commit version or profile that does not actually carry `commit_AAD.sdMerkleRoot`.

### M.3 Required caveats by context

For cleartext fields: state that the value is delivered to the partner and must be protected by the partner.

For low-entropy predicates: state the fact revealed and avoid implying broader secrecy.

For historical/pre-0x0301 builds: state the actual binding level from the commit schema; do not retrofit `commit_AAD.sdMerkleRoot` into old commitments.

For Mode B: state that TEE-side SD is unavailable; client-side SD is a separate future architecture.

For revocation: state that revocation marks a proof no longer acceptable; it does not erase copies already received by the partner.

### M.4 Internal review lint

Before any external text ships, run a text search for:

- "partial unlock"
- "partial release"
- "later proof"
- "learns nothing"
- "fully private disclosure"
- "Mode B SD"
- "revocation deletes"
- "AEAD-bound SD"
- "any predicate"

Every hit requires manual review. Some phrases may appear in a banned-phrasing list like this appendix; outside such lists they are suspect.
