#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE="docker compose"
# Prefer podman-compose if docker compose is not available
if ! $COMPOSE version &>/dev/null 2>&1; then
    if command -v podman-compose &>/dev/null; then
        COMPOSE="podman-compose"
    else
        echo "ERROR: Neither 'docker compose' nor 'podman-compose' found" >&2
        exit 1
    fi
fi

cleanup() {
    echo "=== Cleanup ==="
    $COMPOSE down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Building and starting containers ==="
$COMPOSE up -d --build

# Wait a moment for the sssd-oidc container to be fully up
sleep 2

PASSED=0
FAILED=0

run_test() {
    local name="$1"
    shift
    echo ""
    echo "=== Test: $name ==="
    if "$@"; then
        echo "  PASS: $name"
        ((PASSED++))
    else
        echo "  FAIL: $name"
        ((FAILED++))
    fi
}

# --- Test 1: NSS .so files are installed ---
test_nss_so_installed() {
    $COMPOSE exec -T sssd-oidc test -f /usr/lib/x86_64-linux-gnu/libnss_oidc.so.2
}

# --- Test 2: PAM .so file is installed ---
test_pam_so_installed() {
    $COMPOSE exec -T sssd-oidc test -f /usr/lib/x86_64-linux-gnu/security/pam_oidc.so
}

# --- Test 3: nsswitch.conf references oidc ---
test_nsswitch() {
    $COMPOSE exec -T sssd-oidc grep -q "oidc" /etc/nsswitch.conf
}

# --- Test 4: NSS user lookup by name ---
test_getent_passwd_alice() {
    local result
    result=$($COMPOSE exec -T sssd-oidc getent passwd alice 2>&1)
    echo "  getent passwd alice → $result"
    echo "$result" | grep -q "alice"
}

# --- Test 5: NSS group lookup by name ---
test_getent_group_engineering() {
    local result
    result=$($COMPOSE exec -T sssd-oidc getent group engineering 2>&1)
    echo "  getent group engineering → $result"
    echo "$result" | grep -q "engineering"
}

# --- Test 6: NSS user lookup by UID (reverse) ---
test_getent_passwd_uid() {
    local passwd_line uid result
    passwd_line=$($COMPOSE exec -T sssd-oidc getent passwd alice 2>&1)
    uid=$(echo "$passwd_line" | cut -d: -f3)
    echo "  alice UID = $uid"
    result=$($COMPOSE exec -T sssd-oidc getent passwd "$uid" 2>&1)
    echo "  getent passwd $uid → $result"
    echo "$result" | grep -q "alice"
}

# --- Test 7: getent passwd (enumerate all users) ---
test_getent_passwd_enumerate() {
    local result
    result=$($COMPOSE exec -T sssd-oidc getent passwd 2>&1)
    echo "  getent passwd output (last 5 lines):"
    echo "$result" | tail -5 | sed 's/^/    /'
    echo "$result" | grep -q "alice"
}

# --- Test 8: Inactive user denied by PAM acct_mgmt ---
test_inactive_user_denied() {
    # pamtester returns non-zero when PAM denies access
    if $COMPOSE exec -T sssd-oidc pamtester oidc disabled_bob acct_mgmt 2>&1; then
        echo "  ERROR: inactive user should have been denied"
        return 1
    else
        echo "  Correctly denied inactive user"
        return 0
    fi
}

# --- Test 9: Active user passes PAM acct_mgmt ---
test_active_user_acct_mgmt() {
    $COMPOSE exec -T sssd-oidc pamtester oidc alice acct_mgmt 2>&1
}

# --- Test 10: Offline fallback (cached user still resolves) ---
test_offline_fallback() {
    # First, ensure alice is cached
    $COMPOSE exec -T sssd-oidc getent passwd alice >/dev/null 2>&1

    # Stop the mock IdP
    $COMPOSE stop mock-idp

    # alice should still resolve from cache
    local result
    result=$($COMPOSE exec -T sssd-oidc getent passwd alice 2>&1)
    echo "  Offline getent passwd alice → $result"

    # Restart mock IdP for subsequent tests
    $COMPOSE start mock-idp
    sleep 2

    echo "$result" | grep -q "alice"
}

run_test "NSS .so installed"                test_nss_so_installed
run_test "PAM .so installed"                test_pam_so_installed
run_test "nsswitch.conf has oidc"           test_nsswitch
run_test "getent passwd alice"              test_getent_passwd_alice
run_test "getent group engineering"         test_getent_group_engineering
run_test "getent passwd <UID> (reverse)"    test_getent_passwd_uid
run_test "getent passwd (enumerate)"        test_getent_passwd_enumerate
run_test "Inactive user denied (PAM)"       test_inactive_user_denied
run_test "Active user passes acct_mgmt"     test_active_user_acct_mgmt
run_test "Offline cache fallback"           test_offline_fallback

echo ""
echo "==========================================="
echo "  Results: $PASSED passed, $FAILED failed"
echo "==========================================="

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi

echo "=== ALL TESTS PASSED ==="
