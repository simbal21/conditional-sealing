/**
 * PII allow-list per S2-6 §0.9 line 69 + §1.5 lines 100–102.
 *
 * §0.9 names what ceremony outputs MAY contain:
 *   "registry ids, hashes, block numbers, CIDs, encrypted blobs, role ids,
 *    and event ids."
 *
 * §1.5 names what events MUST NOT contain:
 *   "σ bytes, share bytes, DEK, plaintext, ciphertext, or oracle attestation
 *    plaintext."
 *
 * §0.9 names additional forbidden categories:
 *   "Shamir shares, DEK, oracle attestation plaintext, subject identity, or
 *    sensitive refusal text."
 *
 * Refusal codes `0x02` and `0x03` default to encrypted-reason mode per §0.9.
 *
 * Per S2-6 §14.7 + §16.4, dry-run output MUST also honor `public-copy-sensitive`
 * markers — equivalent discipline as production logs.
 *
 * The allow-list is POSITIVE: any field whose key is NOT on this list is
 * rejected at log-emission time with `CEREMONY_ERR_PII_IN_LOG`.
 *
 * Foundation test `pii-log-wrapper.test.ts` covers (a) allowed-field
 * emission succeeds, (b) forbidden-field emission throws PII_IN_LOG, (c)
 * `--dry-run` output goes through the same gate.
 */
export const LOG_FIELD_ALLOW_LIST: readonly string[] = Object.freeze([
  // Identifiers
  "ceremonyId",
  "proposalHash",
  "entryId",
  "registryName",
  "ceremonyName",
  "ceremonySlug",
  "specSection",
  "actor",
  "phase",
  "subClass",
  // Roles
  "roleId",
  "roleName",
  "grantor",
  "grantee",
  // Hashes / CIDs (content addressing only; never plaintext)
  "manifestHash",
  "disclosureCid",
  "disclosureCommitHash",
  "metadataHash",
  "buildHash",
  "buildEnvDigest",
  "sourceCommitDigest",
  "testVectorDigest",
  "auditDigest",
  "vettingDigest",
  "schemaHash",
  "validExamplesHash",
  "invalidExamplesHash",
  "vendorRoot",
  "teeMeasurement",
  "dcapVerifierRef",
  "binaryHash",
  "authorityPubkey",
  "g4AuthorityRef",
  "oldEntryRef",
  "newEntryRef",
  "tombstoneBlockForOld",
  "quoteProofDigest",
  "userDataDigest",
  "depCidHash",
  "lockfileDigest",
  "semverDigest",
  "rolloutChannel",
  "signedManifestHash",
  "supportedProfileHash",
  "disabledProfileHash",
  "minCombinerSdkVersion",
  "supportedCommitVersionRange",
  "interpreterBytecodeHash",
  "contractAddressHash",
  "astVersion",
  "capSetHash",
  "compatibilityStatementHash",
  "predicateBinaryHash",
  "gasBound",
  "timeBoundMs",
  "allowedInputSchemaRef",
  "operatorPubkeyHash",
  "operatorContactHash",
  "uptimeReputationHash",
  "oracleTypeHash",
  "qtspProviderNameDigest",
  "qtspJurisdictionRef",
  "qtspRootPubkeyHash",
  "eIdasStatusUrlHash",
  "trustListEvidenceHash",
  "supportedQesBundleProfile",
  "counselReviewDigest",
  "shamirShareCount",
  "stanzaGenerationSupport",
  "commitGenerationN",
  "lineageRoot",
  "superseededCommitRef",
  "superseededCommitRefSpelling",
  "recipientId",
  "recipientPubkey",
  "ackDigest",
  "subClassNumber",
  "validatorRuleHash",
  "diffHash",
  "templateId",
  "defaultRowHash",
  "inspectionRenderingHash",
  "simulationVectorHash",
  "authorLockReviewHash",
  "resolverAction",
  "challengeId",
  "extensionDeadline",
  "challengeBondAmount",
  "newOwnerAddress",
  "newThreshold",
  "advisorSeatProofHash",
  "memberAdded",
  "memberRemoved",
  "affectedSurface",
  "rollbackBound",
  "replacementStaged",
  "stagedReplacementRef",
  "durationSeconds",
  "extensionSeconds",
  "pdaScope",
  "reasonDigest",
  "unpauseReasonDigest",
  "legalBasisDigest",
  "emergencyDurationSeconds",
  "emergencyScopeHash",
  "phase2Verified",
  "timestampUnix",
  "pdaRoot",
  "hCommit",
  "oldHCommit",
  "newHCommit",
  "sdMerkleRoot",
  "auditLogRoot",
  "sourceVaultRoot",
  "destinationVaultRoot",
  "sourceAuditLogRoot",
  "destinationAuditLogRoot",
  "migrationManifestHash",
  "retentionStateRoot",
  "shredStateRoot",
  "postureAnnouncementHash",
  "resolverActionRef",
  "evidenceRef",
  "rollbackBound",
  "notificationHash",
  "publicInputsHash",
  // Block numbers / heights
  "effectiveBlock",
  "tombstoneBlock",
  "commitBlock",
  "blockNumber",
  "blockHeight",
  "queueBlock",
  "executeBlock",
  "timelockExpiry",
  "startBlock",
  "expiryBlock",
  "minLatencyBlocks",
  // Tx context
  "txHash",
  "chainId",
  "logIndex",
  // Codes
  "reasonCode",
  "errorCode",
  "stage",
  "governancePath",
  "trustTier",
  "commitVersion",
  "commitGeneration",
  // Encrypted-only payload pointers (never the plaintext)
  "encryptedReasonBlobHash",
  "encryptedDisclosureBlobHash",
  // Authority modes (Pause / Shred enums)
  "pauseAuthorityMode",
  "pauseAuthorityId",
  "shredAuthorityMode",
  "shredAuthorityId",
  "authorityMode",
  "authorizationId",
  "challengeId",
  "violatingFieldName",
  // Governance bookkeeping
  "thresholdCount",
  "ownerCount",
  "safeAddress",
  "actorKind",
  "dryRun",
  "logFile",
  "timestampUnix",
  "eventName",
  // Public-copy markers
  "publicCopySensitive",
]);

const ALLOW_SET: ReadonlySet<string> = new Set(LOG_FIELD_ALLOW_LIST);

export function isAllowedField(key: string): boolean {
  return ALLOW_SET.has(key);
}

/**
 * Banned key names — explicit reject list of categories §1.5 calls out. Any
 * match is a hard reject even if the key fuzzes close to an allow-list
 * entry.
 */
export const LOG_FIELD_DENY_LIST: readonly string[] = Object.freeze([
  "sigma",
  "sigmaBytes",
  "sigmaLit",
  "sigmaG3",
  "sigmaG4",
  "sigmaSubject",
  "share",
  "shareBytes",
  "shamirShare",
  "dek",
  "fileKey",
  "plaintext",
  "cleartext",
  "ciphertext",
  "oraclePlaintext",
  "oracleAttestationPlaintext",
  "refusalReasonText",
  "refusalText",
  "subjectIdentity",
  "subjectName",
  "subjectEmail",
  "subjectDob",
  "subjectAddress",
  "subjectNationalId",
  "kycPayload",
  "rawAttestation",
  "decapKey",
  "wrappedDek",
  "stanzaPayload",
  "envelopeBytes",
]);

const DENY_SET: ReadonlySet<string> = new Set(LOG_FIELD_DENY_LIST);

export function isDeniedField(key: string): boolean {
  return DENY_SET.has(key);
}

/**
 * Compatibility check applied to every field emitted by the log wrapper.
 * Returns true iff the field is on the allow-list AND not on the deny-list
 * (allow-list discipline is positive; deny-list is a belt-and-braces).
 */
export function isPiiSafeField(key: string): boolean {
  if (DENY_SET.has(key)) return false;
  return ALLOW_SET.has(key);
}
