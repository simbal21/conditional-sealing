import type { RegistrySnapshotRef, RevealArtifactBundle, VerifyCheck } from "../types.js";
import {
  failCheck,
  isHex32,
  normalizeHex32,
  passCheck,
  recordValue,
  safeRefsFromBundle,
} from "./canonicalization.js";

export function checkRegistrySnapshots(bundle: RevealArtifactBundle): VerifyCheck {
  const refs = safeRefsFromBundle(bundle);
  const snapshots = bundle.registry_snapshots;
  if (snapshots.authorization_block !== bundle.authorization.authorization_block) {
    return failCheck("REGISTRY_SNAPSHOTS.AUTHORIZATION_BLOCK_MISMATCH", "Registry snapshot block does not match authorization block.", refs);
  }
  if (normalizeHex32(snapshots.authorization_block_hash) !== normalizeHex32(bundle.authorization.authorization_block_hash)) {
    return failCheck("REGISTRY_SNAPSHOTS.AUTHORIZATION_HASH_MISMATCH", "Registry snapshot block hash does not match authorization hash.", refs);
  }
  const namedRefs = [
    snapshots.pda_registry,
    snapshots.condition_module_registry,
    snapshots.shred_registry,
    snapshots.issuer_registry,
    snapshots.attestor_registry,
    snapshots.sd_registry,
    ...Object.values(snapshots.registry_contracts),
    ...Object.values(recordValue(snapshots.gate_authority_registries)),
  ].filter((ref): ref is RegistrySnapshotRef => ref !== undefined);
  for (const ref of namedRefs) {
    if (!isValidRegistryRef(ref)) {
      return failCheck("REGISTRY_SNAPSHOTS.MALFORMED_REF", "Registry snapshot ref is malformed.", {
        ...refs,
        registry_ref: ref.registry_name,
      });
    }
  }
  return passCheck("REGISTRY_SNAPSHOTS.PASS", refs);
}

function isValidRegistryRef(ref: RegistrySnapshotRef): boolean {
  return (
    ref.registry_name.length > 0 &&
    ref.chain_id > 0 &&
    ref.registry_address.length > 0 &&
    ref.checked_block >= 0 &&
    isHex32(ref.checked_block_hash) &&
    isHex32(ref.entry_digest)
  );
}
