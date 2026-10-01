#!/usr/bin/env bash
# DRIFT DISCLAIMER: the deployed bytecode was deployed before the final source snapshot
# and may lag/diverge from this source; testnet-only, never externally audited — see deployments/README.md.
# Live testnet smoke test for V3 deployment.
# Probes the deployed ConditionEngine + governance contracts on Base Sepolia
# to verify post-deploy invariants.

set -uo pipefail

cd "$(dirname "$0")/.."

CE=0xb09a8300423ca3bd0e028bab6a6245a248520d02
TIMELOCK=0x7b60022D7c87ca8f4323B51623109F639A3829FA
DEPLOYER=0xE7c218e9d2910b6aC62fd046268Bc8623f348585
RPC=https://sepolia.base.org

# Role hashes
ROLE_DEFAULT_ADMIN=0x0000000000000000000000000000000000000000000000000000000000000000
ROLE_UPGRADER=$(cast keccak "UPGRADER_ROLE")
ROLE_ORCHESTRATOR=$(cast keccak "ORCHESTRATOR_ROLE")
ROLE_OPERATOR=$(cast keccak "OPERATOR_ROLE")
ROLE_MODULE_ADMIN=$(cast keccak "MODULE_ADMIN_ROLE")

PASS=0
FAIL=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "  PASS: $label"
    PASS=$((PASS+1))
  else
    echo "  FAIL: $label — expected=$expected actual=$actual"
    FAIL=$((FAIL+1))
  fi
}

check_role() {
  local label="$1" role="$2" account="$3" expected="$4"
  local actual
  actual=$(cast call "$CE" "hasRole(bytes32,address)(bool)" "$role" "$account" --rpc-url "$RPC" 2>/dev/null)
  assert_eq "$label" "$expected" "$actual"
}

echo "=== V3 Live Testnet Smoke Test (Base Sepolia chain 84532) ==="
echo ""
echo "[1/4] Role topology — Timelock handoff verification"
check_role "DEFAULT_ADMIN_ROLE held by TimelockController" "$ROLE_DEFAULT_ADMIN" "$TIMELOCK" "true"
check_role "DEFAULT_ADMIN_ROLE revoked from deployer (post handoff)" "$ROLE_DEFAULT_ADMIN" "$DEPLOYER" "false"
check_role "UPGRADER_ROLE held by TimelockController" "$ROLE_UPGRADER" "$TIMELOCK" "true"
check_role "UPGRADER_ROLE revoked from deployer" "$ROLE_UPGRADER" "$DEPLOYER" "false"

echo ""
echo "[2/4] Operational role grants (PostDeploy)"
check_role "ORCHESTRATOR_ROLE granted to deployer-as-temp-admin" "$ROLE_ORCHESTRATOR" "$DEPLOYER" "true"
check_role "OPERATOR_ROLE granted to deployer-as-temp-admin" "$ROLE_OPERATOR" "$DEPLOYER" "true"
check_role "MODULE_ADMIN_ROLE granted to TimelockController" "$ROLE_MODULE_ADMIN" "$TIMELOCK" "true"

echo ""
echo "[3/4] Universal tripwire — lifecycle defaults"
state=$(cast call "$CE" "lifecycleState(bytes32)(uint8)" 0x0000000000000000000000000000000000000000000000000000000000000001 --rpc-url "$RPC" 2>/dev/null)
assert_eq "Unknown auth returns LifecycleState.Unregistered (0)" "0" "$state"

echo ""
echo "[4/4] Negative-path: hCommitForAuthorization on unknown reverts"
ret=$(cast call "$CE" "hCommitForAuthorization(bytes32)(bytes32)" 0x0000000000000000000000000000000000000000000000000000000000000001 --rpc-url "$RPC" 2>&1)
if echo "$ret" | grep -q "execution reverted"; then
  echo "  PASS: hCommitForAuthorization correctly reverts for unknown auth"
  PASS=$((PASS+1))
else
  echo "  FAIL: hCommitForAuthorization did not revert"
  FAIL=$((FAIL+1))
fi

echo ""
echo "========================================"
echo "Result: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "V3 testnet smoke test: ALL PASS" || echo "V3 testnet smoke test: FAILURES present"
exit $FAIL
