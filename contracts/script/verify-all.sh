#!/usr/bin/env bash
# DRIFT DISCLAIMER: the deployed bytecode was deployed before the final source snapshot
# and may lag/diverge from this source; testnet-only, never externally audited — see deployments/README.md.
# Batch Sourcify verification for V3 testnet deployment.
# Compatible with macOS bash 3.2 (no associative arrays).

set -uo pipefail

cd "$(dirname "$0")/.."

BROADCAST_JSON="broadcast/Deploy.s.sol/84532/run-latest.json"
[[ -f "$BROADCAST_JSON" ]] || { echo "Missing $BROADCAST_JSON"; exit 1; }

source_for() {
  case "$1" in
    CealisTimelockController) echo "src/governance/CealisTimelockController.sol" ;;
    CealisSecurityMultisig)   echo "src/governance/CealisSecurityMultisig.sol" ;;
    EmergencyGovernance)      echo "src/governance/EmergencyGovernance.sol" ;;
    CealisIdentifierHelpers)  echo "src/helpers/CealisIdentifierHelpers.sol" ;;
    PluginHashRegistry)       echo "src/registries/PluginHashRegistry.sol" ;;
    G4AuthorityRegistry)      echo "src/registries/G4AuthorityRegistry.sol" ;;
    DSLVersionRegistry)       echo "src/registries/DSLVersionRegistry.sol" ;;
    OracleRegistry)           echo "src/registries/OracleRegistry.sol" ;;
    OracleSchemaRegistry)     echo "src/registries/OracleSchemaRegistry.sol" ;;
    QTSPRegistry)             echo "src/registries/QTSPRegistry.sol" ;;
    GateRecipientPubkeyRegistry) echo "src/gate-recipient/GateRecipientPubkeyRegistry.sol" ;;
    LitV3Assignment)          echo "src/lit/LitV3Assignment.sol" ;;
    DisclosureRevocationRegistry) echo "src/disclosure/DisclosureRevocationRegistry.sol" ;;
    DisclosureRegistry)       echo "src/disclosure/DisclosureRegistry.sol" ;;
    G4RefusalRegistry)        echo "src/g4-refusal/G4RefusalRegistry.sol" ;;
    PasskeyRotationLog)       echo "src/passkey/PasskeyRotationLog.sol" ;;
    SupersededCommitRegistry) echo "src/superseded/SupersededCommitRegistry.sol" ;;
    ChallengeRegistry)        echo "src/challenge/ChallengeRegistry.sol" ;;
    ClaimDSL)                 echo "src/dsl/ClaimDSL.sol" ;;
    FSMInterpreter)           echo "src/fsm/FSMInterpreter.sol" ;;
    PaymentObligationModule)  echo "src/modules/PaymentObligationModule.sol" ;;
    TimeLockModule)           echo "src/modules/TimeLockModule.sol" ;;
    SubjectInitiatedModule)   echo "src/modules/SubjectInitiatedModule.sol" ;;
    HeartbeatMissedModule)    echo "src/modules/HeartbeatMissedModule.sol" ;;
    OracleAttestationModule)  echo "src/modules/OracleAttestationModule.sol" ;;
    MultiPartySignalModule)   echo "src/modules/MultiPartySignalModule.sol" ;;
    DeadManSwitchModule)      echo "src/modules/DeadManSwitchModule.sol" ;;
    ConsentGateModule)        echo "src/modules/ConsentGateModule.sol" ;;
    ComposedModule)           echo "src/modules/ComposedModule.sol" ;;
    AttestationGate)          echo "src/attestation/AttestationGate.sol" ;;
    ShredRegistry)            echo "src/shred/ShredRegistry.sol" ;;
    ConditionEngine)          echo "src/engine/ConditionEngine.sol" ;;
    *) echo "" ;;
  esac
}

VERIFIED=0
SKIPPED=0
FAILED=0

TUPLES=$(python3 -c "
import json
with open('$BROADCAST_JSON') as f:
    data = json.load(f)
seen = set()
for t in data['transactions']:
    addr = t.get('contractAddress')
    name = t.get('contractName')
    if addr and name and (addr, name) not in seen:
        seen.add((addr, name))
        print(f'{addr}|{name}')
")

while IFS='|' read -r addr name; do
  [[ -z "$addr" ]] && continue
  if [[ "$name" == "ERC1967Proxy" ]]; then
    echo "[SKIP proxy] $addr ($name) — OZ-standard"
    SKIPPED=$((SKIPPED+1))
    continue
  fi
  src=$(source_for "$name")
  if [[ -z "$src" ]]; then
    echo "[SKIP unknown] $addr ($name)"
    SKIPPED=$((SKIPPED+1))
    continue
  fi
  echo "[VERIFY] $addr ($name)"
  if forge verify-contract "$addr" "${src}:${name}" --chain-id 84532 --verifier sourcify 2>&1 | grep -E "Submitted|already verified|Error"; then
    VERIFIED=$((VERIFIED+1))
  else
    FAILED=$((FAILED+1))
  fi
  sleep 1
done <<< "$TUPLES"

echo "========================================"
echo "Verified: $VERIFIED  Skipped: $SKIPPED  Failed: $FAILED"
