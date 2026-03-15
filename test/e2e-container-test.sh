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
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: $name"
        FAILED=$((FAILED + 1))
    fi
}

# --- Test 1: NSS .so files are installed ---
test_nss_so_installed() {
    $COMPOSE exec -T sssd-oidc sh -c 'test -f /usr/lib/$(uname -m)-linux-gnu/libnss_oidc.so.2'
}

# --- Test 2: PAM .so file is installed ---
test_pam_so_installed() {
    $COMPOSE exec -T sssd-oidc sh -c 'test -f /usr/lib/$(uname -m)-linux-gnu/security/pam_oidc.so'
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

# --- Test 11: getent group <GID> (reverse lookup) ---
test_getent_group_gid() {
    local group_line gid result
    group_line=$($COMPOSE exec -T sssd-oidc getent group engineering 2>&1)
    gid=$(echo "$group_line" | cut -d: -f3)
    echo "  engineering GID = $gid"
    result=$($COMPOSE exec -T sssd-oidc getent group "$gid" 2>&1)
    echo "  getent group $gid → $result"
    echo "$result" | grep -q "engineering"
}

# --- Test 12: getent group (enumerate all groups) ---
test_getent_group_enumerate() {
    local result
    result=$($COMPOSE exec -T sssd-oidc getent group 2>&1)
    echo "  getent group output (last 5 lines):"
    echo "$result" | tail -5 | sed 's/^/    /'
    echo "$result" | grep -q "engineering"
}

# --- Test 13: Group membership includes alice ---
test_group_membership() {
    local result members
    result=$($COMPOSE exec -T sssd-oidc getent group engineering 2>&1)
    echo "  getent group engineering → $result"
    members=$(echo "$result" | cut -d: -f4)
    echo "  members field = $members"
    echo "$members" | grep -q "alice"
}

# --- Test 14: Non-existent user returns nothing ---
test_nonexistent_user() {
    if $COMPOSE exec -T sssd-oidc getent passwd nonexistent_user_xyz 2>&1 | grep -q "nonexistent_user_xyz"; then
        echo "  ERROR: non-existent user should not resolve"
        return 1
    else
        echo "  Correctly returned nothing for non-existent user"
        return 0
    fi
}

# --- Test 15: Non-existent group returns nothing ---
test_nonexistent_group() {
    if $COMPOSE exec -T sssd-oidc getent group nonexistent_group_xyz 2>&1 | grep -q "nonexistent_group_xyz"; then
        echo "  ERROR: non-existent group should not resolve"
        return 1
    else
        echo "  Correctly returned nothing for non-existent group"
        return 0
    fi
}

# --- Test 16: Inactive user still resolves via NSS ---
test_inactive_user_resolves_nss() {
    local result
    result=$($COMPOSE exec -T sssd-oidc getent passwd disabled_bob 2>&1)
    echo "  getent passwd disabled_bob → $result"
    echo "$result" | grep -q "disabled_bob"
}

# --- Test 17: id alice shows supplementary groups (initgroups_dyn) ---
test_id_alice_groups() {
    local result
    result=$($COMPOSE exec -T sssd-oidc id alice 2>&1)
    echo "  id alice → $result"
    echo "$result" | grep -q "engineering"
}

# --- Test 18: Offline group fallback ---
test_offline_group_fallback() {
    # First, ensure engineering is cached
    $COMPOSE exec -T sssd-oidc getent group engineering >/dev/null 2>&1

    # Stop the mock IdP
    $COMPOSE stop mock-idp

    # engineering should still resolve from cache
    local result
    result=$($COMPOSE exec -T sssd-oidc getent group engineering 2>&1)
    echo "  Offline getent group engineering → $result"

    # Restart mock IdP for subsequent tests
    $COMPOSE start mock-idp
    sleep 2

    echo "$result" | grep -q "engineering"
}

# --- Test 19: Non-existent user still fails offline ---
test_offline_nonexistent_user() {
    # Ensure cache is populated with known users
    $COMPOSE exec -T sssd-oidc getent passwd alice >/dev/null 2>&1

    # Stop the mock IdP
    $COMPOSE stop mock-idp

    # Non-existent user should still not resolve
    if $COMPOSE exec -T sssd-oidc getent passwd nonexistent_user_xyz 2>&1 | grep -q "nonexistent_user_xyz"; then
        # Restart mock IdP
        $COMPOSE start mock-idp
        sleep 2
        echo "  ERROR: non-existent user should not resolve offline"
        return 1
    else
        echo "  Correctly returned nothing for non-existent user offline"
        # Restart mock IdP
        $COMPOSE start mock-idp
        sleep 2
        return 0
    fi
}

# --- Test 20: UID is deterministic across lookups ---
test_uid_deterministic() {
    local uid1 uid2
    uid1=$($COMPOSE exec -T sssd-oidc getent passwd alice 2>&1 | cut -d: -f3)
    uid2=$($COMPOSE exec -T sssd-oidc getent passwd alice 2>&1 | cut -d: -f3)
    echo "  First lookup UID  = $uid1"
    echo "  Second lookup UID = $uid2"
    [ "$uid1" = "$uid2" ]
}

# --- Test 21: Passwd field format is correct ---
test_passwd_field_format() {
    local result
    result=$($COMPOSE exec -T sssd-oidc getent passwd alice 2>&1)
    echo "  getent passwd alice → $result"
    # Format: alice:x:<uid>:<gid>:Alice Smith:/home/alice:/bin/bash
    echo "$result" | grep -qE '^alice:x:[0-9]+:[0-9]+:Alice Smith:/home/alice:/bin/bash$'
}

# --- Test 22: Config file is present ---
test_config_present() {
    $COMPOSE exec -T sssd-oidc test -f /etc/sssd-oidc/config.toml
}

run_test "NSS .so installed"                test_nss_so_installed
run_test "PAM .so installed"                test_pam_so_installed
run_test "nsswitch.conf has oidc"           test_nsswitch
run_test "Config file present"              test_config_present
run_test "getent passwd alice"              test_getent_passwd_alice
run_test "getent group engineering"         test_getent_group_engineering
run_test "getent passwd <UID> (reverse)"    test_getent_passwd_uid
run_test "getent group <GID> (reverse)"     test_getent_group_gid
run_test "getent passwd (enumerate)"        test_getent_passwd_enumerate
run_test "getent group (enumerate)"         test_getent_group_enumerate
run_test "Group membership includes alice"  test_group_membership
run_test "Non-existent user"                test_nonexistent_user
run_test "Non-existent group"               test_nonexistent_group
run_test "Inactive user resolves (NSS)"     test_inactive_user_resolves_nss
run_test "Inactive user denied (PAM)"       test_inactive_user_denied
run_test "Active user passes acct_mgmt"     test_active_user_acct_mgmt
run_test "id alice (initgroups)"            test_id_alice_groups
run_test "UID is deterministic"             test_uid_deterministic
run_test "Passwd field format"              test_passwd_field_format
run_test "Offline cache fallback"           test_offline_fallback
run_test "Offline group fallback"           test_offline_group_fallback
run_test "Offline non-existent user fails"  test_offline_nonexistent_user

echo ""
echo "==========================================="
echo "  Results: $PASSED passed, $FAILED failed"
echo "==========================================="

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi

echo "=== ALL TESTS PASSED ==="
