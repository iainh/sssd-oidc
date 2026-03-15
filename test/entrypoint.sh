#!/bin/sh
# Entrypoint for e2e test container.
# Sets up alice's home dir and SSH authorized_keys using her NSS-resolved UID/GID,
# then starts sshd and sleeps.

set -e

# Resolve alice's UID and GID from NSS (our oidc module)
if getent passwd alice >/dev/null 2>&1; then
    ALICE_UID=$(getent passwd alice | cut -d: -f3)
    ALICE_GID=$(getent passwd alice | cut -d: -f4)
    ALICE_HOME=$(getent passwd alice | cut -d: -f6)

    mkdir -p "${ALICE_HOME}/.ssh"
    cp /tmp/ssh_test_key.pub "${ALICE_HOME}/.ssh/authorized_keys"
    chmod 700 "${ALICE_HOME}/.ssh"
    chmod 600 "${ALICE_HOME}/.ssh/authorized_keys"
    chown -R "${ALICE_UID}:${ALICE_GID}" "${ALICE_HOME}"
fi

# Start sshd in the background
/usr/sbin/sshd

# Keep the container running
exec /bin/sleep infinity
